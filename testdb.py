from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import NoResultFound, MultipleResultsFound, IntegrityError

from multicred import schema
from multicred import credentials


ENGINE = create_engine('sqlite://', echo=True, future=True)
schema.Base.metadata.create_all(ENGINE)
SM = sessionmaker(bind=ENGINE, future=True)
SESSION1 = SM()


acct1=schema.AwsAccountStorage(account_id='9191')
SESSION1.add(acct1)
SESSION1.commit()
acct2=schema.AwsAccountStorage(account_id='9292')
SESSION1.add(acct2)
SESSION1.commit()
SESSION1.close()

SESSION2 = SM()
print(SESSION2.query(schema.AwsAccountStorage).all())
