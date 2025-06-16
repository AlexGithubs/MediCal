# MediCal - Prescription Reminder System

A secure, web-based medication reminder system with Epic FHIR integration and email notifications.

![MediCal Interface](https://img.shields.io/badge/Status-Production%20Ready-green)
![Security](https://img.shields.io/badge/Security-Client%20Side%20Only-blue)
![Integration](https://img.shields.io/badge/Epic%20FHIR-Supported-orange)

## Features

- 📅 **Smart Calendar Views**: Day, 3-day, week, and month views
- 🏥 **Epic FHIR Integration**: Import medications directly from Epic MyChart
- 📧 **Email Reminders**: Automated email notifications for medication times
- 🔒 **Privacy First**: All data stored locally in your browser
- 📱 **Responsive Design**: Works on desktop, tablet, and mobile
- 🎨 **Visual Tracking**: Color-coded medications with food instructions
- 📊 **History Tracking**: Complete medication adherence history

## Quick Start

### 1. Clone and Setup

```bash
git clone <your-repo-url>
cd MediCal
```

### 2. Configure API Keys

Copy the configuration template:

```bash
cp config.example.js config.js
```

Edit `config.js` with your actual API keys:

```javascript
const CONFIG = {
    EPIC_FHIR: {
        CLIENT_ID_PRODUCTION: 'your_epic_client_id_here',
        USE_PRODUCTION: true,
    },
    RESEND: {
        API_KEY: 'your_resend_api_key_here',
        FROM_EMAIL: 'noreply@yourdomain.com',
    }
};
```

### 3. Serve the Application

Open `index.html` in your browser or serve it via a local server:

```bash
# Using Python 3
python -m http.server 8000

# Using Node.js
npx http-server

# Using PHP
php -S localhost:8000
```

Then visit `http://localhost:8000`

## Configuration Guide

### Epic FHIR Setup

1. **Register for Epic FHIR Access**
   - Visit [Epic FHIR](https://fhir.epic.com)
   - Create a developer account
   - Register your application

2. **Get Your Client ID**
   - Production Client IDs start with 'd'
   - Sandbox Client IDs start with 'c'

3. **Configure OAuth Redirect**
   - Set redirect URI to your domain (e.g., `https://yourdomain.com/`)
   - For local development: `http://localhost:8000/`

4. **Update config.js**
   ```javascript
   EPIC_FHIR: {
       CLIENT_ID_PRODUCTION: 'd1234567-abcd-1234-abcd-123456789012',
       USE_PRODUCTION: true,  // Set to false for sandbox
   }
   ```

### Email Setup (Resend)

1. **Create Resend Account**
   - Visit [Resend.com](https://resend.com)
   - Sign up for free account
   - Verify your email domain

2. **Get API Key**
   - Go to API Keys section
   - Create new API key
   - Copy the key (starts with 're_')

3. **Update config.js**
   ```javascript
   RESEND: {
       API_KEY: 're_your_api_key_here',
       FROM_EMAIL: 'noreply@yourdomain.com',
   }
   ```

## Security & Privacy

### 🔒 Data Protection
- **Local Storage Only**: All medication data stays in your browser
- **No External Servers**: Patient data never leaves your device
- **Secure APIs**: All API calls use HTTPS and OAuth 2.0
- **Input Validation**: All user inputs are sanitized and validated

### 🛡️ Security Features
- XSS Protection
- SQL Injection Prevention
- Patient ID Validation
- Automatic Data Backups
- Error Logging & Recovery

### 🚨 Important Security Notes
- Never share your Patient ID publicly
- Only use your own Patient ID or that of someone you're authorized to care for
- Keep your API keys secure and never commit them to version control
- Use HTTPS in production environments

## Usage

### Adding Medications

1. **Manual Entry**
   - Click "Add Prescription" button
   - Fill in medication details
   - Set reminder times and preferences

2. **Epic FHIR Import**
   - Go to Settings tab
   - Enter your Epic MyChart Patient ID
   - Enable "Epic FHIR Integration"
   - Click "Save Settings"
   - Authenticate with Epic when prompted

### Email Reminders

1. **Configure Email**
   - Go to Settings tab
   - Enter your email address
   - Enable "Email reminders"
   - Set daily summary preferences

2. **Automatic Reminders**
   - Reminders sent based on medication schedule
   - Configurable reminder time (5-120 minutes before dose)
   - Daily summary emails available

### Calendar Navigation

- **View Options**: Switch between Day, 3-Day, Week, and Month views
- **Navigation**: Use arrow buttons or "Today" button
- **Interactions**: Click on medications to mark as taken/skipped
- **Visual Cues**: Color coding and food instruction indicators

## Demo Mode

The application includes a comprehensive demo mode:

- **Sample Medications**: Pre-loaded with realistic medication data
- **Simulated APIs**: Mock Epic FHIR and email responses
- **Full Functionality**: All features work without real API keys
- **Learning Tool**: Perfect for testing and learning the interface

## Development

### File Structure

```
MediCal/
├── index.html          # Main application page
├── styles.css          # Application styles
├── script.js           # Main application logic
├── config.js           # API configuration (excluded from git)
├── config.example.js   # Configuration template
├── README.md           # This file
├── .gitignore          # Git ignore rules
├── cert.pem           # SSL certificate (if needed)
└── key.pem            # SSL private key (if needed)
```

### Key Classes

- **`EpicFHIRClient`**: Handles Epic FHIR API integration
- **`ResendClient`**: Manages email notifications
- **`PrescriptionReminderApp`**: Main application controller

### Browser Compatibility

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Troubleshooting

### Common Issues

**"Configuration not loaded" error**
- Ensure `config.js` exists and is properly formatted
- Check that `config.js` is loaded before `script.js` in HTML

**Epic FHIR not connecting**
- Verify your Client ID is correct
- Check that redirect URI matches exactly
- Ensure you're using the right environment (production vs sandbox)

**Email reminders not working**
- Verify your Resend API key is correct
- Check that your from email domain is verified
- Ensure email address is properly configured in settings

**Patient ID not accepted**
- Patient IDs must be alphanumeric with hyphens, underscores, or dots
- Maximum 64 characters
- Contact your healthcare provider if you're unsure of the format

### Debug Commands

Open browser console and try:

```javascript
// Check configuration status
console.log(CONFIG);

// Test email setup
testEmailSetup();

// Test FHIR setup
testFHIRSetup();

// Clean up duplicate prescriptions
cleanupDuplicates();

// Create manual backup
createBackup();
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the troubleshooting section
- Review the browser console for error messages

## Acknowledgments

- [Epic FHIR](https://fhir.epic.com) for healthcare data integration
- [Resend](https://resend.com) for reliable email delivery
- [Inter Font](https://fonts.google.com/specimen/Inter) for typography

---

**⚠️ Medical Disclaimer**: This application is for medication reminder purposes only and does not replace professional medical advice. Always consult with your healthcare provider for medical decisions. 