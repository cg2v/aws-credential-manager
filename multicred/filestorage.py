from pathlib import Path
from configparser import ConfigParser

from . import credentials
from .interfaces import IdentityHandle

class FileStorage:
    _root: Path

    reserved_names = {"identity.ini", "current"}
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

    def _get_idini_path(self, id_path: Path) -> Path:
        return id_path.joinpath("identity.ini")

    def _get_idini(self, id_path: Path) -> ConfigParser:
        inifile = self._get_idini_path(id_path)
        if not inifile.exists():
            raise ValueError(f"Identity {id_path} does not have an ini file")
        config = ConfigParser(delimiters=('='), interpolation=None)
        config.read(inifile)
        return config

    def _update_idini(self, id_path: Path, config: ConfigParser) -> None:
        inifile = self._get_idini_path(id_path)
        with inifile.open("w", encoding="ASCII") as file:
            config.write(file)

    def _get_handle_from_path(self, path: Path) -> IdentityHandle:
        config = self._get_idini(path)
        arn = config.get("identity", "arn")
        role_session_name = config.get("identity", "role_session_name", fallback=None)
        userid = config.get("identity", "userid")
        if role_session_name:
            return credentials.AwsRoleIdentity(arn, userid, role_session_name)
        return credentials.AwsIdentity(arn, userid)

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
        id_path = self._get_path_from_identity(identity)
        config = self._get_idini(id_path)
        if 'parent' not in config:
            return None, None
        parent_arn = config.get("parent", "parent_arn")
        parent_role = config.get("parent", "role_arn")
        parent_id = self.get_identity_by_arn(parent_arn)
        if parent_id is None:
            return None, None
        return parent_id, parent_role

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
        config = self._get_idini(id_path)
        if 'parent' not in config:
            config.add_section('parent')
        config.set('parent', 'parent_arn', parent_creds.aws_identity.aws_identity)
        config.set('parent', 'role_arn', role_arn)
        self._update_idini(id_path, config)
        parent_path = self._get_path_from_identity(parent_creds.aws_identity)
        parent_config = self._get_idini(parent_path)
        if 'children' not in parent_config:
            parent_config.add_section('children')
        parent_config.set('children', creds.aws_identity.arn, role_arn)
        self._update_idini(parent_path, parent_config)

    def remove_identity_relationship(self, identity: IdentityHandle) -> None:
        id_path = self._get_path_from_identity(identity)
        if not id_path.exists():
            return
        if not id_path.is_dir():
            raise ValueError(f"Identity path {id_path} is not a directory")
        config = self._get_idini(id_path)
        # XXX the test is bad and requires the child exception to be raised
        # even if there are no parents
        if 'children' in config and len(config.options('children')) > 0:
            raise ValueError("This identity has dependent children")
        if 'parent' not in config:
            return
        parent_arn = config.get("parent", "parent_arn")
        parent = self.get_identity_by_arn(parent_arn)
        if parent is not None:
            parent_path = self._get_path_from_identity(parent)
            parent_config = self._get_idini(parent_path)
            if 'children' in parent_config:
                if parent_config.remove_option('children', identity.arn):
                    self._update_idini(parent_path, parent_config)

        config.remove_section('parent')
        self._update_idini(id_path, config)

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
            if cred_link.name in self.reserved_names:
                continue
            allcreds_link = self._root.joinpath("all_credentials", cred_link.name)
            if allcreds_link.exists():
                allcreds_link.unlink()
            cred_link.unlink()
