# Use offical python image as base

FROM python:3.10-slim

# SET WORKING DIRECTORY
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cahce-dir -r requirements.txt


# copy tall proje t ciles to container
COPY . .

# Expose Streamlitu default port
EXPOSE 8501

# Command to run the Streamlit app
CMD ["streamlit", "run", "app.py"]