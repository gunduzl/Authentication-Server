<style>
  .title {
    text-align: center;
    font-size: 36px;
    color: #3498db; /* Blue color */
  }

  .author {
    text-align: center;
    font-style: italic;
    color: #e74c3c; /* Red color */
  }

  .report {
    text-align: center;
    font-size: 28px;
    color: #2ecc71; /* Green color */
  }
</style>

<p class="title">CSE439 TERM PROJECT</p>

<p class="author">By</p>

<p>Abdurrahman Gündüzlü</p>

<p class="report">AUTHENTICATION AND AUTHORIZATION SERVER DESIGN</p>

<p>Project Report</p>



![DESIGN](https://github.com/gunduzl/Authentication-Server/assets/69585166/2e76cb1a-f467-4aa2-87f0-6bedcb02bb2d)


Design and Code Explanation Overview: 

The goal of this RESTful project is to have a FastAPI application that implements an authentication and authorization system inspired by Kerberos-like principles. This system includes features such as user authentication, token generation, key updates, and logging. The application is structured with specific routes, each serving a unique function.

Components: 

1. **Database Models:**  
   1. **Person:** Represents user data, including username, full name, email, hashed client key, account status, admin status, and Ticket Granting Ticket (TGT). 
   1. **SecretKeyTable:** Stores the secret key and algorithm used for JWT token generation. 
   1. **Log:** Records various events with information such as status, username, timestamp, and a message. 
1. **Token Models:**  
- **Token:** Represents the structure of the JWT token. 
- **TokenData:** Represents the payload data extracted from the JWT token. 
- **TgsResponse:** Represents the response structure for Ticket Granting Service (TGS) requests. 
- **UpdateClientKey, UpdateServerKey, client\_tgt, UserResponse:** Various models for different functionalities. 
3. **Security and Authentication:**  
   1. **OAuth2PasswordBearer:** FastAPI security dependency for handling OAuth2 password flow. 
   1. **CryptContext:** Manages password hashing and verification using the bcrypt scheme. 
   1. **generate\_new\_server\_key:** Function to generate a new server key using openssl. 
   1. **create\_access\_token:** Generates a JWT token with an expiration time. 
3. **Helper Functions:**  
- Functions like get\_db, get\_secret\_key\_and\_algorithm, verify\_password, get\_password\_hash, get\_user, authenticate\_user, istanbul\_time, add\_log\_entry, and decrypt\_message support various functionalities. 
5. **Routes:**  
   1. **/token (POST):** Handles user login, decrypts the password, and issues an access token. 
   1. **/tgt-validation-and-tgs (POST):** Validates a Ticket Granting Ticket (TGT) and issues a TGS token. 
   1. **/users/me (GET):** Retrieves user information based on the current user's token. 
   1. **/update-client-key (POST):** Updates the client key for the current user. 
   1. **/update-server-key (POST):** Updates the server key (admin-only). 
   1. **/generate-new-server-key (GET):** Generates a new server key (admin-only). 
   1. **/current-time (GET):** Retrieves the current time in the Europe/Istanbul timezone. 
   1. **/users (GET):** Retrieves user information (TGS validation). 
   1. **/logout (GET):** Logs the user out and removes the Ticket Granting Ticket. 
5. **Main Block:**  
- The application runs using Uvicorn on 127.0.0.1:8000, and integration tests validate the system's behavior. 

Implementations 

1. Imports: 
- **FastAPI-related Imports:**  
- Core FastAPI components like FastAPI, HTTPException, status, Depends, File, UploadFile. 
- Components for OAuth2-based password authentication (OAuth2PasswordBearer, OAuth2PasswordRequestForm). 
- **Data Modeling and ORM Imports:**  
- Pydantic class (BaseModel) for defining data models. 
- SQLAlchemy classes (Column, Integer, String, Boolean) for defining database table columns. 
- SQLAlchemy classes (declarative\_base, sessionmaker) for ORM. 
- **Cryptography and Security-related Imports:**  
- Passlib library (CryptContext) for securely hashing passwords. 
- Libraries for JWT encoding and decoding (jwt). 
- Functions for parsing query strings (parse\_qsl). 
- Libraries for RSA encryption and decryption (rsa). 
- Library for base64 encoding/decoding (base64). 
- **Database and ORM Setup Imports:**  
- SQLAlchemy function for creating a database engine (create\_engine). 
- SQLAlchemy class for declarative table class definition (declarative\_base). 
- **External Process and OS-related Imports:**  
- Python modules for running external processes (subprocess). 
- Python module for interacting with the operating system (os). 
- **Date and Time-related Imports:**  
- Python modules for working with dates and times (datetime, timedelta). 
- Library for handling time zones (pytz). 
- **FastAPI Development Server Import:**  
- ASGI server for running FastAPI applications (uvicorn). 
2. Database: 

**Database Initialization:** 

- Connection URL for the PostgreSQL database (DATABASE\_URL). 
- Creating a database engine using SQLAlchemy for database interaction (create\_engine). 
- Initializing database tables based on declared Base models (Base.metadata.create\_all(bind=engine)). 

**SQLAlchemy ORM Models:** 

- SQLAlchemy declarative models (Person, SecretKeyTable, Log) representing database tables for storing user information, secret keys, and log entries. 

**Database Session Management:** 

- Factory function for creating a SQLAlchemy database session (SessionLocal). 
- FastAPI dependency function for obtaining a database session (get\_db). 

**User Authentication and Authorization:** 

- **Password Handling:**  
- Functions for verifying passwords (verify\_password) and hashing passwords (get\_password\_hash). 
- **User Authentication:**  
- Function for authenticating users (authenticate\_user). 
- **JWT Token Operations:**  
- Functions for generating JWT tokens (create\_access\_token). 
- FastAPI dependency functions for retrieving the current user and ensuring the user is active. 

**Logging and Time Functions:** 

- Functions for obtaining the current time in the Europe/Istanbul timezone (istanbul\_time). 
- Function for adding log entries to the database (add\_log\_entry). 

**Key and Algorithm Operations:** 

- Function for generating a new server key using openssl (generate\_new\_server\_key). 

**Encryption and Decryption Functions:** 

- Function for decrypting messages using RSA encryption (decrypt\_message). 

**FastAPI Endpoints:** 

- Endpoints for user login, TGT validation, TGS, user information retrieval, client key update, server key update, server key generation, current time retrieval, user information retrieval (TGS validation), and user logout. 

4\. Security Considerations: 

- Passwords are securely hashed using bcrypt. 
- JWT tokens are used for authentication and authorization. 
- Logging is implemented to track user activities and potential errors. 
