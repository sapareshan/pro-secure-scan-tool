from typing import List
from typing import Optional
# from sqlalchemy import ForeignKey
# from sqlalchemy import String
# from sqlalchemy.orm import DeclarativeBase
# from sqlalchemy.orm import Mapped
# from sqlalchemy.orm import mapped_column
# from sqlalchemy.orm import relationship
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker , relationship
from sqlalchemy.types import JSON
from sqlalchemy.orm import Session
# from sqlalchemy.orm import sessionmaker, scoped_session
# from contextlib import contextmanager




Base = declarative_base()



# Define the CompanyInfo model
class CompanyInfo(Base):
    __tablename__ = 'company_info'

    id = Column(Integer, primary_key=True, autoincrement=True)
    temp_id = Column(Integer, unique=True, nullable=False)
    company_name = Column(String(255), nullable=True, default="Unknown")
    email = Column(String(255), nullable=True, unique=False)
    url = Column(String(255), nullable=True)
    otp = Column(Integer, nullable=True)

    def __repr__(self):
        return f"<CompanyInfo(id={self.id}, company_name={self.company_name}, email={self.email})>"

# Define the Vulnerability model
class Vulnerabilities(Base):
    __tablename__ = 'vulnerabilities'

    company_id = Column(Integer, ForeignKey('company_info.id'), primary_key=True)  # Foreign Key & Primary Key
    missing_headers = Column(JSON, nullable=True)  # JSON type for missing headers
    ports = Column(JSON, nullable=True)  # Port field as a string, or Integer if you prefer
    vulnerabilities_ports = Column(JSON, nullable=True)  # ✅ Store version-based vulnerabilities
    info_http_headers = Column(JSON, nullable=True) 
    technology_info = Column(JSON, nullable=True)  # ✅ Store all details in JSON format
    xss_vulnerabilities = Column(JSON, nullable=True)
    open_redirection_vulnerabilities = Column(JSON, nullable=True)
    Directory_enumration_vulnerabilities = Column(JSON, nullable=True)
    clickjacking_vulnerability = Column(JSON, nullable=True)
    #os_command_injection_vulnerabilities = Column(JSON, nullable=True)


    # Define the relationship to CompanyInfo
    company = relationship("CompanyInfo", backref="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerabilities(company_id={self.company_id}, ports={self.ports}, missing_headers={self.missing_headers})>"
    
'''

  
engine = create_engine('mysql+pymysql://root:kali@localhost/pro_secure_labs');

# Session factory, bound to the engine
Session = sessionmaker(bind=engine)
'''
# Create a new session




def get_db_session():
    engine = create_engine('mysql+pymysql://root:kali@localhost/pro_secure_labs', pool_pre_ping=True)
    Session = sessionmaker(bind=engine)
    return Session()

# session = get_db_session()

'''

SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
@contextmanager
def get_db_session():
    session = SessionLocal()
    try:
        yield session  # Provide session to the caller
        session.commit()  # Commit changes if no errors occur
    except Exception as e:
        session.rollback()  # Rollback if an error occurs
        raise e  # Re-raise the exception
    finally:
        session.close()  # Ensure session is closed

def some_function():
    with get_db_session() as session:
        user = session.query(user).filter_by(username="admin").first()
        print(user)        
'''




# Session = sessionmaker(bind=engine);
# session = Session();

#session.commit()

# ✅ Function to initialize database

engine = create_engine('mysql+pymysql://root:kali@localhost/pro_secure_labs', pool_pre_ping=True)
def init_db():
    Base.metadata.create_all(engine)
    print("Database tables created successfully!")  # ✅  Added a success message


def addSoftwareVersion():
       # Check if 'software_version' column exists in 'vulnerabilities' table
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("vulnerabilities")]

    if "software_version" not in columns:
        with engine.connect() as connection:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN software_version JSON NULL;"))
            print("✅ Column 'software_version' added to vulnerabilities table!")


def addSoftwareVersionInVulnerabilities():
       # Check if 'software_version_vulnerabilities' column exists in 'vulnerabilities' table
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("vulnerabilities")]

    if "software_version_vulnerable" not in columns:
        with engine.connect() as connection:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN software_version_vulnerable JSON NULL;"))
            print("✅ Column 'software_version_vulnerable' added to vulnerabilities table!")            


def addhttpHeaders():
       # Check if 'vulnurability ports' column exists in 'vulnerabilities' table
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("vulnerabilities")]

    if "info_http_headers" not in columns:
        with engine.connect() as connection:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN info_http_headers JSON NULL;"))
            print("✅ Column 'info_http_headers' added to vulnerabilities table!")     


def addCompanyInfo():
       # Check if 'vulnurability ports' column exists in 'vulnerabilities' table
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("vulnerabilities")]

    if "technology_info" not in columns:
        with engine.connect() as connection:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN technology_info JSON NULL;"))
            print("✅ Column 'technology_info' added to vulnerabilities table!")     

def addXSSColumn():
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("vulnerabilities")]

    if "xss_vulnerabilities" not in columns:
        with engine.connect() as connection:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN xss_vulnerabilities JSON NULL;"))
            print("✅ Column 'xss_vulnerabilities' added to vulnerabilities table!")                           


def addOpenRedirection():
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("vulnerabilities")]

    if "open_redirection_vulnerabilities" not in columns:
        with engine.connect() as connection:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN open_redirection_vulnerabilities JSON NULL;"))
            print("✅ Column 'open_redirection_vulnerabilities' added to vulnerabilities table!")                                   

def addDirectoryEnumration():
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("vulnerabilities")]

    if "Directory_enumration_vulnerabilities" not in columns:
        
        with engine.connect() as connection:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN Directory_enumration_vulnerabilities JSON NULL;"))
            print("✅ Column 'Directory_enumration_vulnerabilities' added to vulnerabilities table!")     




def addClickjackingVulnerability():
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("vulnerabilities")]

    if "clickjacking_vulnerability" not in columns:
        
        with engine.connect() as connection:
            connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN clickjacking_vulnerability JSON NULL;"))
            print("✅ Column 'clickjacking_vulnerability' added to vulnerabilities table!")                 

# def addCommandInjection():
#     inspector = inspect(engine)
#     columns = [col["name"] for col in inspector.get_columns("vulnerabilities")]

#     if "os_command_injection_vulnerabilities" not in columns:
#         with engine.connect() as connection:
#             connection.execute(text("ALTER TABLE vulnerabilities ADD COLUMN os_command_injection_vulnerabilities JSON NULL;"))
#             print("✅ Column 'os_command_injection_vulnerabilities' added to vulnerabilities table!") 

def addOtpInCompanyInfo():
    inspector = inspect(engine)
    columns = [col["name"] for col in inspector.get_columns("company_info")]

    try:
        if "otp" not in columns:
            with engine.connect() as connection:
                connection.execute(text("ALTER TABLE company_info ADD COLUMN otp INT NULL;"))
                print("otp column added succesfully in company_info table")
    except Exception as e:
        print(f"Something went wrong, {e}")


def runExtraQueries():
    addCompanyInfo();
    addSoftwareVersion();
    addSoftwareVersionInVulnerabilities();
    addhttpHeaders();
    addXSSColumn();
    addOpenRedirection();
    addDirectoryEnumration();
    addClickjackingVulnerability();
    addOtpInCompanyInfo();

    # addCommandInjection();

 




# 🔹 Initialize database on import
# init_db()