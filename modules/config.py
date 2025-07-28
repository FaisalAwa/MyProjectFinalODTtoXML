# Image Types Supported:
# - QuestionDescriptionImage: Regular description images (ContentType: Image)
# - QuestionOptionImage: Question option images for processing
# - AnswerOptionImage: Answer option images for processing  
# - JustDropDown: Special dropdown images
# - PositionedImage: Positioned element images
# - BackgroundImage: Background images for positioned questions (ContentType: BImage)

"""
Configuration settings for the ODT processor application.
"""

import streamlit as st
import toml
import os

# Try to load secrets from Secrets/secrets.toml

try:
    secrets = toml.load(".streamlit/secrets.toml")
    # API Settings from local secrets
    GEMINI_API_KEY = secrets['general']['GEMINI_API_KEY']
    ANTHROPIC_API_KEY = secrets['general']['ANTHROPIC_API_KEY']
    GEMINI_MODEL = secrets['general']['GEMINI_MODEL']
except (FileNotFoundError, KeyError):
    # Fall back to Streamlit Cloud secrets
    GEMINI_API_KEY = st.secrets['general']['GEMINI_API_KEY']
    ANTHROPIC_API_KEY = st.secrets['general']['ANTHROPIC_API_KEY']
    GEMINI_MODEL = st.secrets['general']['GEMINI_MODEL']

# Question Types
QUESTION_TYPES = [
    "HOTSPOT",
    "DRAGDROP", 
    "DROPDOWN", 
    "RADIOBUTTON", 
    "MULTIPLECHOICE",
    "FILLINTHEBLANK",
    "SIMULATION",
    "POSITIONEDDROPDOWN",
    "POSITIONEDDRAGDROP"  
]

# API Retry Settings
MAX_API_RETRIES = 3
RETRY_DELAY_BASE = 2  # seconds

# Image Processing
MINIMUM_IMAGE_SIZE = 100  # bytes, for considering an image valid

# App Settings
APP_TITLE = "ODT to XML Complete Processing "
APP_DESCRIPTION = "This application processes ODT files sequentially, maintaining the natural order of content and using Gemini to analyze images."