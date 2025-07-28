import mysql.connector
from mysql.connector import Error

def create_connection():
    """Create a connection to the MySQL database"""
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='fais914!',  
            database='streamlit_app'
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# ...existing code...

def verify_admin(username, password):
    """
    Verify admin credentials against the database.
    
    Args:
        username (str): Admin username
        password (str): Admin password
        
    Returns:
        bool: True if credentials are valid, False otherwise
    """
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM admin WHERE username = %s AND password = %s",
            (username, password)
        )
        result = cursor.fetchone()
        return result is not None
    except Exception as e:
        print(f"Error verifying admin: {e}")
        return False
    finally:
        conn.close()

def verify_user(username, password):
    """Verify if the username and password match in the database"""
    connection = create_connection()
    if connection is None:
        return False
    
    try:
        cursor = connection.cursor()
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        return result is not None
    except Error as e:
        print(f"Error: {e}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def create_user(username, password):
    """Create a new user in the database
    Returns (success, message) tuple"""
    connection = create_connection()
    if connection is None:
        return False, "Database connection failed"
    
    try:
        cursor = connection.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return False, f"Username '{username}' already exists"
        
        # Create new user
        query = "INSERT INTO users (username, password) VALUES (%s, %s)"
        cursor.execute(query, (username, password))
        connection.commit()
        return True, "User created successfully"
    except Error as e:
        return False, str(e)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Add this after your existing functions
def log_user_activity(username, action, ip_address=None, user_agent=None):
    """
    Log user activity in the database
    
    Parameters:
    - username: The username of the user
    - action: The action performed ('login', 'logout', 'failed_login')
    - ip_address: The IP address of the user (optional)
    - user_agent: The user agent of the user's browser (optional)
    
    Returns:
    - True if logging was successful, False otherwise
    """
    connection = create_connection()
    if connection is None:
        return False
    
    try:
        cursor = connection.cursor()
        
        # Insert log record
        query = """
            INSERT INTO user_logs (username, action, ip_address, user_agent) 
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (username, action, ip_address, user_agent))
        connection.commit()
        return True
    except Error as e:
        print(f"Error logging user activity: {e}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_user_login_stats(username=None, days=30):
    """
    Get login statistics for users
    
    Parameters:
    - username: Optional username to filter by
    - days: Number of days to look back (default 30)
    
    Returns:
    - Dictionary with login statistics
    """
    connection = create_connection()
    if connection is None:
        return None
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Base query parts
        select_clause = """
            SELECT username, 
                   COUNT(CASE WHEN action = 'login' THEN 1 END) as login_count,
                   COUNT(CASE WHEN action = 'failed_login' THEN 1 END) as failed_login_count,
                   MIN(CASE WHEN action = 'login' THEN timestamp END) as first_login,
                   MAX(CASE WHEN action = 'login' THEN timestamp END) as last_login
        """
        from_clause = " FROM user_logs "
        where_clause = f" WHERE timestamp >= DATE_SUB(NOW(), INTERVAL {days} DAY) "
        group_clause = " GROUP BY username "
        
        # Add username filter if provided
        if username:
            where_clause += " AND username = %s "
            query = select_clause + from_clause + where_clause + group_clause
            cursor.execute(query, (username,))
        else:
            query = select_clause + from_clause + where_clause + group_clause
            cursor.execute(query)
        
        # Get results
        results = cursor.fetchall()
        return results
    except Error as e:
        print(f"Error getting login stats: {e}")
        return None
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()