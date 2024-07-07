from pathlib import Path
import warnings
from configparser import ConfigParser
from dataclasses import dataclass

from . import credentials
from .interfaces import IdentityHandle

@dataclass(frozen=True, eq=False)
class FileStorageIdentityHandle:
    _arn: str
    _account_id: int
    _cred_type: credentials.CredentialType
    _name: str

    @property
    def account_id(self) -> int:
        return self._account_id

    @property
    def arn(self) -> str:
        return self._arn

    @property
    def cred_type(self) -> credentials.CredentialType:
        return self._cred_type

    @property
    def name(self) -> str:
        return self._name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IdentityHandle):
            return False
        return self.arn == other.arn

    def __hash__(self) -> int:
        return hash(self.arn)

class FileStorage:
    _root: Path

    def __init__(self, root: Path | str):
        self._root = Path(root)
        if not self._root.exists():
            self._root.mkdir()
        if not self._root.is_dir():
            raise ValueError(f"{root} is not a directory")
        marker = self._root.joinpath('.multicred.marker')
        if not list(self._root.iterdir()):
            marker.touch()
        if not marker.exists():
            raise ValueError(f"Folder {root} does not belong to multicred")

    def _get_handle_from_ini(self, inifile: Path) -> IdentityHandle:
        config = ConfigParser()
        config.read(inifile)
        arn = config.get("identity", "arn")
        role_session_name = config.get("identity", "role_session_name", fallback=None)
        userid = config.get("identity", "userid", fallback=None)
        if role_session_name:
            return credentials.AwsRoleIdentity(arn, userid or '', role_session_name)
        return credentials.AwsIdentity(arn, userid or '')


    def _get_handle_from_path(self, path: Path) -> IdentityHandle:
        newpath = path.resolve().relative_to(self._root)
        components = newpath.parts
        account_id = int(components[1])
        cred_type = credentials.CredentialType(components[2])
        name = components[3]
        inifile = path.joinpath("identity.ini")
        if inifile.exists():
            return self._get_handle_from_ini(inifile)
        warnings.warn(f"Identity {path} does not have an ini file")
        arn = f"arn:aws:sts::{account_id}:{cred_type.value}/{name}"
        return FileStorageIdentityHandle(arn, account_id, cred_type, name)

    def _get_path_from_identity(self, identity: IdentityHandle) -> Path:
        return self._root.joinpath("account_identities",
                                   str(identity.account_id),
                                   identity.cred_type.value,
                                   identity.name)

    def _create_identity_path(self, creds: credentials.Credentials) -> Path:
        id_path = self._get_path_from_identity(creds.aws_identity)
        if not id_path.exists():
            id_path.mkdir(parents=True)
        if not id_path.is_dir():
            raise ValueError(f"Identity path {id_path} is not a directory")
        inifile = id_path.joinpath("identity.ini")
        if not inifile.exists():
            config = ConfigParser()
            config.add_section("identity")
            config.set("identity", "arn", creds.aws_identity.aws_identity)
            config.set("identity", "userid", creds.aws_identity.aws_userid)
            config.set("identity", "cred_type", creds.aws_identity.cred_type.value)
            if creds.aws_identity.cred_type == credentials.CredentialType.ROLE:
                assert isinstance(creds.aws_identity, credentials.AwsRoleIdentity)
                config.set("identity", "role_session_name",
                            creds.aws_identity.aws_role_session_name)
            with inifile.open("w", encoding="ASCII") as file:
                config.write(file)
        arndir = self._root.joinpath("identity_arns")
        if not arndir.exists():
            arndir.mkdir()
        link_target_path = Path(
            "..", id_path.resolve().relative_to(self._root))
        arnlink_name = creds.aws_identity.arn.replace(":", "_").replace("/", "_")
        arn_link_path = arndir.joinpath(arnlink_name)
        if not arn_link_path.exists():
            arn_link_path.symlink_to(link_target_path)
        return id_path
    def get_identity_by_arn(self, arn: str) -> IdentityHandle | None:
        arnpath = self._root.joinpath(
            "identity_arns", arn.replace(":", "_").replace("/", "_"))
        if not arnpath.exists():
            return None
        return self._get_handle_from_path(arnpath)

    def get_identity_by_account_and_role_name(self, account_id: str, role_name: str) \
        -> IdentityHandle | None:
        accountpath = self._root.joinpath("account_identities", account_id)
        if not accountpath.exists():
            return None
        rolepath = accountpath.joinpath("role", role_name)
        if not rolepath.exists():
            return None
        return self._get_handle_from_path(rolepath)

    def get_parent_identity(self, identity: IdentityHandle):
        if identity.cred_type != credentials.CredentialType.ROLE:
            return None, None
        id_path = self._root.joinpath("account_identities",
                                     str(identity.account_id),
                                     "role",
                                     identity.name)
        parent_link = id_path.joinpath("parent_link")
        if not parent_link.exists():
            return None, None
        parent_role_path = id_path.joinpath("parent_role")
        parent_role = parent_role_path.read_text(encoding="ASCII").strip()
        return self._get_handle_from_path(parent_link), parent_role

    def construct_identity_relationship(self, creds: credentials.Credentials,
                                    parent_creds: credentials.Credentials,
                                    role_arn: str) \
                                        -> None:
        if creds.aws_identity.cred_type != credentials.CredentialType.ROLE:
            raise ValueError("Can only construct relationships for roles")
        id_path = self._get_path_from_identity(creds.aws_identity)
        if not id_path.exists():
            id_path.mkdir(parents=True)
        if not id_path.is_dir():
            raise ValueError(f"Identity path {id_path} is not a directory")
        parent_link = id_path.joinpath("parent_link")
        parent_role_path = id_path.joinpath("parent_role")
        parent_link_target = self._get_path_from_identity(parent_creds.aws_identity)
        link_target_base = id_path.parent
        link_target_prefix = Path("..")
        while True:
            try:
                parent_link_target = parent_link_target.relative_to(link_target_base)
                break
            except ValueError as e:
                if link_target_base == self._root:
                    raise ValueError("Parent identity is not in the same root") from e
                link_target_base = link_target_base.parent
                link_target_prefix = link_target_prefix.joinpath("..")
        parent_link.symlink_to(link_target_prefix.joinpath(parent_link_target))
        parent_role_path.write_text(role_arn, encoding="ASCII")

    def remove_identity_relationship(self, identity: IdentityHandle) -> None:
        id_path = self._get_path_from_identity(identity)
        if not id_path.exists():
            return
        if not id_path.is_dir():
            raise ValueError(f"Identity path {id_path} is not a directory")
        # XXX doesn't check if this is a parent
        parent_link = id_path.joinpath("parent_link")
        parent_role_path = id_path.joinpath("parent_role")
        parent_link.unlink(missing_ok=True)
        parent_role_path.unlink(missing_ok=True)

    def import_credentials(self, creds: credentials.Credentials, force: bool = False) -> None:
        id_path = self._create_identity_path(creds)
        cred_path = id_path.joinpath(creds.aws_access_key_id)
        if cred_path.exists() and not force:
            raise ValueError("Credentials already exist")
        with cred_path.open("w", encoding="ASCII") as file:
            config = ConfigParser()
            config.add_section("credentials")
            config.set("credentials", "aws_access_key_id", creds.aws_access_key_id)
            config.set("credentials", "aws_secret_access_key", creds.aws_secret_access_key)
            if creds.aws_session_token:
                config.set("credentials", "aws_session_token", creds.aws_session_token)
            if creds.aws_identity.cred_type == credentials.CredentialType.ROLE:
                config.set("credentials", "x_role_arn", creds.aws_identity.aws_identity)
                assert isinstance(creds.aws_identity, credentials.AwsRoleIdentity)
                config.set("credentials", "x_role_session_name",
                           creds.aws_identity.aws_role_session_name)
                config.set("credentials", "x_userid", creds.aws_identity.aws_userid)
            elif creds.aws_identity.cred_type == credentials.CredentialType.USER:
                config.set("credentials", "x_userid", creds.aws_identity.aws_userid)
            config.write(file)
        current_link = id_path.joinpath("current")
        current_link_target = cred_path.resolve().relative_to(id_path)
        if current_link.exists():
            current_link.unlink()
        current_link.symlink_to(current_link_target)
        allcreds_path = self._root.joinpath("all_credentials")
        if not allcreds_path.exists():
            allcreds_path.mkdir()
        if not allcreds_path.is_dir():
            raise ValueError(f"Credentials path {allcreds_path} is not a directory")
        cred_link_target_1 = cred_path.resolve().relative_to(self._root)
        cred_link_target = Path("..", cred_link_target_1)
        allcreds_link = allcreds_path.joinpath(creds.aws_access_key_id)
        allcreds_link.symlink_to(cred_link_target)

    def get_identity_credentials(self, identity: IdentityHandle) -> credentials.Credentials | None:
        id_path = self._get_path_from_identity(identity)
        cred_link = id_path.joinpath("current")
        if not cred_link.exists():
            return None
        cred_path = cred_link.resolve()
        config = ConfigParser()
        config.read(cred_path)
        rv = credentials.Credentials(
            aws_access_key_id=config.get("credentials", "aws_access_key_id"),
            aws_secret_access_key=config.get("credentials", "aws_secret_access_key"),
            aws_session_token=config.get("credentials", "aws_session_token", fallback=None),
        )
        if not rv.is_valid:
            rv.aws_identity = credentials.AwsIdentity(
                aws_identity=identity.arn,
                aws_userid=identity.name
            )
        return rv

    def get_credentials_by_key(self, access_key: str) -> credentials.Credentials | None:
        allcreds_path = self._root.joinpath("all_credentials")
        if not allcreds_path.exists():
            return None
        if not allcreds_path.is_dir():
            raise ValueError(f"Credentials path {allcreds_path} is not a directory")
        cred_path = allcreds_path.joinpath(access_key)
        if not cred_path.is_file() or not cred_path.exists():
            return None
        config = ConfigParser()
        config.read(cred_path)
        return credentials.Credentials(
            aws_access_key_id=config.get("credentials", "aws_access_key_id"),
            aws_secret_access_key=config.get("credentials", "aws_secret_access_key"),
            aws_session_token=config.get("credentials", "aws_session_token", fallback=None)
        )

    def delete_credentials_by_key(self, access_key: str) -> None:
        allcreds_path = self._root.joinpath("all_credentials")
        if not allcreds_path.exists():
            return
        if not allcreds_path.is_dir():
            raise ValueError(f"Credentials path {allcreds_path} is not a directory")
        allcreds_link = allcreds_path.joinpath(access_key)
        cred_link_target = allcreds_link.resolve()
        cred_link_id = cred_link_target.parent
        id_current_creds = cred_link_id.joinpath("current")
        if id_current_creds.samefile(cred_link_target):
            id_current_creds.unlink()
        allcreds_link.unlink()
        cred_link_target.unlink()

    def purge_identity_credentials(self, identity: IdentityHandle) -> None:
        id_path = self._get_path_from_identity(identity)
        if not id_path.exists():
            return
        if not id_path.is_dir():
            raise ValueError(f"Identity path {id_path} is not a directory")
        current_link = id_path.joinpath("current")
        if current_link.exists():
            current_link.unlink()
        for cred_link in id_path.iterdir():
            allcreds_link = self._root.joinpath("all_credentials", cred_link.name)
            if allcreds_link.exists():
                allcreds_link.unlink()
            cred_link.unlink()
        id_path.rmdir()
