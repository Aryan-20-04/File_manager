import bcrypt

#convert the password to bcrypt
def hash_password(password: str)-> str:
    """Hash a password for storing."""
    hashed=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
    return hashed.decode('utf-8')

 
def verify_password(stored_hash_password: str,input_password: str)->bool:
    '''Verify if the user password is correct against a stored hash password'''
    return bcrypt.checkpw(input_password.encode('utf-8'),stored_hash_password.encode('utf-8'))

def main():
    
    #Getting a valid password
    password=input("Enter a password to hash: ")
    if not password:
        print("Password cannot be empty")
        return
    
    #Conversion of password to bcrypt
    hashed_password=hash_password(password)
    
    #Get a valid input
    user_password=input("Enter your password: ")
    if not user_password:
        print("Password cannot be empty")
        return
    
    #Verification of the input password
    if verify_password(hashed_password,user_password):
        print("Password is valid")
    else:
        print("Password is not valid")

    input("Press enter to exit...")

if __name__== "__main__":
    main()
