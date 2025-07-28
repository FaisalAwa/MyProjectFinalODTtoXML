import streamlit as st
import time
from datetime import datetime
from modules.utils.db_connection import verify_user, create_user, log_user_activity, get_user_login_stats, verify_admin
import mysql.connector
from mysql.connector import Error

st.set_page_config(page_title="Login - ODT Processor", layout="centered")

def main():
    st.title("Login")
    
    # If there was a successful login, show message first
    if 'show_login_success' in st.session_state and st.session_state.show_login_success:
        st.success("Login successful!")
        st.info("You can now navigate to the App in the sidebar!")
        # Clear the flag after showing the message
        st.session_state.show_login_success = False
        return
    
    # Create login form
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")
        
        if submit_button:
            if verify_user(username, password):
                # Set a success flag and other session data
                st.session_state.show_login_success = True
                st.session_state.logged_in = True
                st.session_state.username = username
                
                # Log successful login
                log_user_activity(
                    username, 
                    'login',
                    ip_address=st.session_state.get('client_ip', None),
                    user_agent=st.session_state.get('user_agent', None)
                )
                
                # Show success message that will persist
                st.success("Login successful!")
                
                # Add a slight delay so message is visible
                time.sleep(2)
                
                # Rerun to update the interface
                st.rerun()
            else:
                # Log failed login attempt
                if username:  # Only log if username was provided
                    log_user_activity(username, 'failed_login')
                st.error("Invalid username or password")
    
    # Add admin functions section
    st.markdown("---")
    st.write("Admin Functions:")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Add New User", key="add_user_btn"):
            st.session_state.page = "add_user"
            st.rerun()
    with col2:
        if st.button("Admin Dashboard", key="admin_dashboard_btn"):
            st.session_state.page = "admin_dashboard"
            st.rerun()



def add_user_page():
    st.title("Add New User")
    
    # Check if we need to show a success message
    if 'user_created' in st.session_state and st.session_state.user_created:
        st.success(f"User '{st.session_state.created_username}' created successfully!")
        # Clear the flag after showing the message
        st.session_state.user_created = False
        time.sleep(2)
        st.session_state.page = "login"
        st.rerun()
        return
    
    with st.form("add_user_form"):
        # Admin verification section
        st.subheader("Admin Verification")
        admin_name = st.text_input("Admin Name")
        admin_password = st.text_input("Admin Password", type="password")
        
        st.subheader("New User Details")
        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        add_button = st.form_submit_button("Create User")
        
        if add_button:
            # First verify admin credentials using database
            if not verify_admin(admin_name, admin_password):
                st.error("Invalid admin credentials. User creation denied.")
            elif new_password != confirm_password:
                st.error("Passwords do not match")
            elif not new_username or not new_password:
                st.error("Username and password are required")
            else:
                success, message = create_user(new_username, new_password)
                if success:
                    # Set success flag and username for display
                    st.session_state.user_created = True
                    st.session_state.created_username = new_username
                    st.rerun()  # Rerun to show success message
                else:
                    st.error(f"Error creating user: {message}")
    
    if st.button("Back to Login", key="back_btn"):
        st.session_state.page = "login"
        st.rerun()



def admin_dashboard():
    st.title("Admin Dashboard")
    
    # Only allow if admin credentials are provided
    with st.form("admin_auth_form"):
        admin_name = st.text_input("Admin Name")
        admin_password = st.text_input("Admin Password", type="password")
        auth_button = st.form_submit_button("Authenticate")
        
        if auth_button:
            # Use database verification instead of hardcoded credentials
            if not verify_admin(admin_name, admin_password):
                st.error("Invalid admin credentials. Access denied.")
                return
            else:
                st.session_state.admin_authenticated = True

    
    # If admin is authenticated, show the dashboard
    if st.session_state.get('admin_authenticated', False):
        st.success("Admin authenticated successfully")
        
        st.subheader("User Login Statistics")
        
        # Get time range for statistics
        col1, col2 = st.columns(2)
        with col1:
            days_filter = st.slider("Days to look back", 1, 90, 30)
        with col2:
            specific_user = st.text_input("Filter by username (leave empty for all users)")
        
        # Get statistics
        stats = get_user_login_stats(
            username=specific_user if specific_user else None, 
            days=days_filter
        )
        
        if stats:
            # Create a DataFrame for display
            import pandas as pd
            df = pd.DataFrame(stats)
            
            # Format the timestamps
            if 'first_login' in df.columns:
                df['first_login'] = pd.to_datetime(df['first_login']).dt.strftime('%Y-%m-%d %H:%M:%S')
            if 'last_login' in df.columns:
                df['last_login'] = pd.to_datetime(df['last_login']).dt.strftime('%Y-%m-%d %H:%M:%S')
            
            # Display the statistics
            st.dataframe(df)
            
            # Display charts
            if len(df) > 0:
                st.subheader("Login Statistics Visualization")
                
                # Bar chart of login counts
                st.bar_chart(df.set_index('username')['login_count'])
                
                # Failed login attempts
                if 'failed_login_count' in df.columns and df['failed_login_count'].sum() > 0:
                    st.subheader("Failed Login Attempts")
                    st.bar_chart(df.set_index('username')['failed_login_count'])
        else:
            st.info("No login data available for the selected criteria")
    
    # Back button
    if st.button("Back", key="admin_back"):
        st.session_state.page = "login"
        if 'admin_authenticated' in st.session_state:
            del st.session_state.admin_authenticated
        st.rerun()

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if 'page' not in st.session_state:
    st.session_state.page = "login"

# Show appropriate page based on session state
if st.session_state.logged_in and st.session_state.page == "login":
    st.success(f"Welcome, {st.session_state.username}!")
    st.info("You are logged in. Please select 'App' from the sidebar to access the main application.")
    
    # Add a logout button
    if st.button("Logout", key="logout_btn"):
        # Log logout
        log_user_activity(st.session_state.username, 'logout')
        
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
elif st.session_state.page == "add_user":
    add_user_page()
elif st.session_state.page == "admin_dashboard":
    admin_dashboard()
else:
    main()