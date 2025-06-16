// ============================================================================
// PRESCRIPTION REMINDER SYSTEM - MAIN APPLICATION WITH EPIC FHIR INTEGRATION
// ============================================================================

// FHIR Client for Epic Integration
class EpicFHIRClient {
    constructor() {
        // Check if CONFIG is available
        if (typeof CONFIG === 'undefined') {
            console.error('❌ Configuration not loaded. Please ensure config.js is included before script.js');
            throw new Error('Configuration not available. Please check config.js file.');
        }

        // Use configuration from config.js
        const epicConfig = CONFIG.EPIC_FHIR;
        
        // Use production or sandbox client ID based on configuration
        this.clientId = epicConfig.USE_PRODUCTION ? 
            epicConfig.CLIENT_ID_PRODUCTION : 
            (epicConfig.CLIENT_ID_SANDBOX || epicConfig.CLIENT_ID_PRODUCTION);
        
        // Epic FHIR endpoints
        this.baseUrl = epicConfig.BASE_URL;
        this.authUrl = epicConfig.AUTH_URL;
        this.tokenUrl = epicConfig.TOKEN_URL;
        
        // CRITICAL: Use Epic's configured redirect URI
        this.redirectUri = window.location.origin + window.location.pathname;
        
        this.accessToken = null;
        this.patientId = null;
        this.maxRetries = CONFIG.APP.MAX_RETRIES;
        this.retryDelay = CONFIG.APP.RETRY_DELAY;
        
        // Security: Input validation patterns
        this.validPatientIdPattern = /^[A-Za-z0-9\-_\.]{1,64}$/; // Alphanumeric, hyphens, underscores, dots, max 64 chars
        this.suspiciousPatterns = [
            /<script/i, /javascript:/i, /on\w+=/i, // XSS patterns
            /union\s+select/i, /drop\s+table/i, // SQL injection patterns
            /\.\.\//g, /\.\.\\/, // Path traversal
            /%[0-9a-f]{2}/i // URL encoding (potential bypass attempts)
        ];
        
        // Check if credentials look like placeholders
        if (this.clientId.includes('YOUR_EPIC') || this.clientId === 'YOUR_EPIC_PRODUCTION_CLIENT_ID_HERE') {
            console.warn('⚠️ Epic FHIR Client ID not configured. FHIR integration will run in demo mode.');
            this.isConfigured = false;
            this.demoMode = true;
        } else {
            this.isConfigured = true;
            this.demoMode = false;
        }
        
        console.log(`🔧 Epic FHIR Configuration:
        Client ID: ${this.clientId}
        Environment: ${this.clientId.startsWith('d') ? 'Production' : 'Non-Production'}
        Redirect URI: ${this.redirectUri}
        Base URL: ${this.baseUrl}
        Mode: ${this.demoMode ? 'Demo' : 'Live'}`);
    }

    // Security: Validate and sanitize patient ID input
    validatePatientId(patientId) {
        if (!patientId || typeof patientId !== 'string') {
            throw new Error('Patient ID is required and must be a string');
        }

        // Remove any whitespace
        const cleanId = patientId.trim();
        
        if (cleanId.length === 0) {
            throw new Error('Patient ID cannot be empty');
        }

        if (cleanId.length > 64) {
            throw new Error('Patient ID is too long (maximum 64 characters)');
        }

        // Check for suspicious patterns
        for (const pattern of this.suspiciousPatterns) {
            if (pattern.test(cleanId)) {
                console.error('Security: Suspicious pattern detected in patient ID:', pattern);
                throw new Error('Invalid patient ID format detected');
            }
        }

        // Validate against allowed pattern
        if (!this.validPatientIdPattern.test(cleanId)) {
            throw new Error('Patient ID contains invalid characters. Only letters, numbers, hyphens, underscores, and dots are allowed.');
        }

        return cleanId;
    }

    // Security: Sanitize HTML content to prevent XSS
    sanitizeHtml(str) {
        if (!str) return '';
        return str.replace(/[<>'"&]/g, (match) => {
            const escapeMap = {
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#x27;',
                '&': '&amp;'
            };
            return escapeMap[match];
        });
    }

    // Enhanced initialization with comprehensive error handling
    async initialize(patientId = null) {
        try {
            // Validate and sanitize patient ID
            if (patientId) {
                this.patientId = this.validatePatientId(patientId);
                console.log('✅ Patient ID validated successfully');
            } else {
                this.patientId = 'eXhIellHdGVYdUhCdEdTcGQzTGRjQTMB'; // Epic sandbox patient fallback
                console.log('ℹ️ Using default sandbox patient ID');
            }
            
            if (!this.isConfigured) {
                if (this.demoMode) {
                    console.log('🧪 FHIR Client running in demo mode');
                    return { success: true, mode: 'demo' };
                } else {
                    throw new Error('Epic FHIR Client ID not configured. Please update the clientId in the EpicFHIRClient constructor.');
                }
            }
            
            // For Epic FHIR, we need to implement proper OAuth flow
            console.log('🔄 Initializing Epic FHIR with OAuth 2.0 flow...');
            return { success: true, mode: 'oauth-required', patientId: this.patientId };
            
        } catch (error) {
            console.error('❌ Failed to initialize FHIR client:', error.message);
            return { success: false, error: error.message };
        }
    }

    // Implement proper Epic OAuth 2.0 flow
    async authenticateWithEpic() {
        if (!this.isConfigured) {
            if (this.demoMode) {
                // Demo mode - simulate authentication
                this.accessToken = 'demo-token';
                console.log('🧪 DEMO MODE - Authentication simulated');
                return { success: true, mode: 'demo' };
            } else {
                throw new Error('Epic FHIR not configured. Please update the credentials in the EpicFHIRClient constructor.');
            }
        }

        try {
            console.log('🔐 Starting Epic OAuth 2.0 authentication flow...');
            
            // Check if we have a stored access token
            const storedToken = localStorage.getItem('epic_access_token');
            const tokenExpiry = localStorage.getItem('epic_token_expiry');
            
            if (storedToken && tokenExpiry && new Date() < new Date(tokenExpiry)) {
                console.log('✅ Using stored access token');
                this.accessToken = storedToken;
                return { success: true, mode: 'stored-token' };
            }
            
            // Need to start OAuth flow
            console.log('🚀 Starting OAuth authorization...');
            this.startOAuthFlow();
            return { success: false, mode: 'oauth-redirect', message: 'Redirecting to Epic for authentication...' };
            
        } catch (error) {
            console.error('❌ Authentication failed:', error);
            throw new Error('Failed to authenticate with Epic FHIR API: ' + error.message);
        }
    }

    // Handle OAuth callback - Epic uses their own redirect endpoint
    async handleOAuthCallback(authCode, state) {
        try {
            // Verify state parameter
            const storedState = localStorage.getItem('oauth_state');
            if (state !== storedState) {
                throw new Error('Invalid OAuth state parameter');
            }
            
            console.log('🔄 Exchanging authorization code for access token...');
            
            // Exchange authorization code for access token
            const tokenResponse = await fetch(this.tokenUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    code: authCode,
                    redirect_uri: this.redirectUri,
                    client_id: this.clientId
                })
            });
            
            if (!tokenResponse.ok) {
                const errorText = await tokenResponse.text();
                throw new Error(`Token exchange failed: ${tokenResponse.status} - ${errorText}`);
            }
            
            const tokenData = await tokenResponse.json();
            
            if (tokenData.error) {
                throw new Error(`OAuth error: ${tokenData.error} - ${tokenData.error_description}`);
            }
            
            // Store access token
            this.accessToken = tokenData.access_token;
            const expiryTime = new Date(Date.now() + (tokenData.expires_in * 1000));
            
            localStorage.setItem('epic_access_token', this.accessToken);
            localStorage.setItem('epic_token_expiry', expiryTime.toISOString());
            localStorage.removeItem('oauth_state');
            
            // Extract patient ID from token if available
            if (tokenData.patient) {
                this.patientId = tokenData.patient;
                console.log('✅ Patient ID from token:', this.patientId);
            }
            
            console.log('✅ Epic OAuth authentication successful');
            
            // Note: With Epic's redirect URI, we don't clean up the URL since we're not on our page
            
            return { success: true, mode: 'oauth-complete', patientId: this.patientId };
            
        } catch (error) {
            console.error('❌ OAuth callback failed:', error);
            localStorage.removeItem('oauth_state');
            throw error;
        }
    }

    // Start OAuth 2.0 authorization flow with Epic's configuration
    startOAuthFlow() {
        const state = this.generateRandomState();
        localStorage.setItem('oauth_state', state);
        
        const authParams = new URLSearchParams({
            response_type: 'code',
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: 'patient/MedicationRequest.read patient/Patient.read',
            state: state,
            aud: this.baseUrl
        });
        
        const authUrl = `${this.authUrl}?${authParams.toString()}`;
        console.log('🔗 Redirecting to Epic OAuth:', authUrl);
        console.log('ℹ️ Note: Epic will redirect back to this page after authentication');
        
        // Redirect to Epic for authentication
        window.location.href = authUrl;
    }

    // Generate random state for OAuth security
    generateRandomState() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // Test FHIR connection with proper authentication
    async testConnection() {
        try {
            if (this.demoMode) {
                return { success: true, mode: 'demo' };
            }

            // For Epic FHIR, we need authentication first
            if (!this.accessToken) {
                return { success: false, error: 'No access token available. Authentication required.' };
            }

            // Test with a simple metadata request
            const response = await fetch(`${this.baseUrl}/metadata`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${this.accessToken}`
                }
            });

            if (response.ok) {
                return { success: true, mode: 'authenticated' };
            } else {
                return { success: false, error: `HTTP ${response.status}: ${response.statusText}` };
            }
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async makeRequest(endpoint, options = {}) {
        const maxRetries = options.maxRetries || this.maxRetries;
        let lastError;
        
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                console.log(`🔄 FHIR API Request (attempt ${attempt}/${maxRetries}): ${endpoint}`);
                
                const url = `${this.baseUrl}${endpoint}`;
                const requestOptions = {
                    method: options.method || 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        ...options.headers
                    },
                    ...options
                };

                // Add authentication header if we have a token
                if (this.accessToken && !this.demoMode) {
                    requestOptions.headers['Authorization'] = `Bearer ${this.accessToken}`;
                }

                const response = await fetch(url, requestOptions);
                
                // Log response details for debugging
                console.log(`📡 Response: ${response.status} ${response.statusText}`);
                
                return response;
                
        } catch (error) {
                lastError = error;
                console.error(`❌ Request attempt ${attempt} failed:`, error.message);
                
                if (attempt < maxRetries) {
                    const delay = Math.pow(2, attempt - 1) * 1000; // Exponential backoff
                    console.log(`⏳ Retrying in ${delay}ms...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                } else {
                    console.error(`❌ All ${maxRetries} attempts failed`);
                }
            }
        }
        
        throw lastError;
    }

    // Enhanced demo request with realistic error simulation
    async makeDemoRequest(endpoint) {
        console.log('🧪 DEMO MODE - Simulating FHIR API request:', endpoint);
        
        // Simulate network delay
        await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));
        
        // Simulate occasional network errors (5% chance)
        if (Math.random() < 0.05) {
            throw new Error('Simulated network error - please retry');
        }

        // Return mock FHIR bundle for MedicationRequest queries
        if (endpoint.includes('MedicationRequest')) {
            return this.generateMockMedicationData();
        }

        if (endpoint.includes('Patient/')) {
            return this.generateMockPatientData();
        }
        
        // Return empty bundle for other requests
        return { resourceType: 'Bundle', total: 0, entry: [] };
    }

    // Generate comprehensive mock medication data
    generateMockMedicationData() {
        const mockMedications = [
            {
                resourceType: 'MedicationRequest',
                id: 'demo-med-1',
                status: 'active',
                intent: 'order',
                medicationCodeableConcept: {
                    coding: [{
                        system: 'http://www.nlm.nih.gov/research/umls/rxnorm',
                        code: '29046',
                        display: 'Lisinopril'
                    }],
                    text: 'Lisinopril'
                },
                dosageInstruction: [{
                    text: 'Take 10mg once daily',
                    timing: {
                        repeat: {
                            frequency: 1,
                            period: 1,
                            periodUnit: 'd',
                            timeOfDay: ['08:00']
                        }
                    },
                    doseAndRate: [{
                        doseQuantity: {
                            value: 10,
                            unit: 'mg'
                        }
                    }],
                    additionalInstruction: [{
                        text: 'For blood pressure control. Take at the same time each day.'
                    }]
                }]
            },
            {
                resourceType: 'MedicationRequest',
                id: 'demo-med-2',
                status: 'active',
                intent: 'order',
                medicationCodeableConcept: {
                    coding: [{
                        system: 'http://www.nlm.nih.gov/research/umls/rxnorm',
                        code: '6809',
                        display: 'Metformin'
                    }],
                    text: 'Metformin'
                },
                dosageInstruction: [{
                    text: 'Take 500mg twice daily with meals',
                    timing: {
                        repeat: {
                            frequency: 2,
                            period: 1,
                            periodUnit: 'd',
                            timeOfDay: ['08:00', '20:00']
                        }
                    },
                    doseAndRate: [{
                        doseQuantity: {
                            value: 500,
                            unit: 'mg'
                        }
                    }],
                    additionalInstruction: [{
                        text: 'Take with food to reduce stomach upset. Monitor blood sugar levels.'
                    }]
                }]
            },
            {
                resourceType: 'MedicationRequest',
                id: 'demo-med-3',
                status: 'active',
                intent: 'order',
                medicationCodeableConcept: {
                    coding: [{
                        system: 'http://www.nlm.nih.gov/research/umls/rxnorm',
                        code: '1998',
                        display: 'Atorvastatin'
                    }],
                    text: 'Atorvastatin'
                },
                dosageInstruction: [{
                    text: 'Take 20mg once daily in the evening',
                    timing: {
                        repeat: {
                            frequency: 1,
                            period: 1,
                            periodUnit: 'd',
                            timeOfDay: ['21:00']
                        }
                    },
                    doseAndRate: [{
                        doseQuantity: {
                            value: 20,
                            unit: 'mg'
                        }
                    }],
                    additionalInstruction: [{
                        text: 'For cholesterol management. Take in the evening for best effectiveness.'
                    }]
                }]
            }
        ];

        return {
            resourceType: 'Bundle',
            total: mockMedications.length,
            entry: mockMedications.map(med => ({ resource: med }))
        };
    }

    // Generate mock patient data
    generateMockPatientData() {
        return {
            resourceType: 'Patient',
            id: this.patientId,
            name: [{
                family: 'Demo',
                given: ['Patient']
            }],
            birthDate: '1950-01-01',
            gender: 'male'
        };
    }

    // Enhanced medication request retrieval with comprehensive error handling
    async getPatientMedicationRequests(patientId) {
        try {
            if (this.demoMode) {
                console.log('🧪 DEMO MODE - Returning mock FHIR data');
                return this.getMockFHIRData();
            }

            // Ensure we have authentication
            if (!this.accessToken) {
                console.log('🔐 No access token available, starting authentication...');
                const authResult = await this.authenticateWithEpic();
                if (!authResult.success) {
                    throw new Error('Authentication required but failed');
                }
            }

            console.log(`🔄 Retrieving medications for patient: ${patientId}`);
            
            const endpoint = `/MedicationRequest?patient=${patientId}&status=active&_count=50`;
            const response = await this.makeRequest(endpoint);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ FHIR API Request failed:', response.status, errorText);
                
                if (response.status === 401) {
                    // Token might be expired, clear it and retry authentication
                    localStorage.removeItem('epic_access_token');
                    localStorage.removeItem('epic_token_expiry');
                    this.accessToken = null;
                    throw new Error('Authentication expired. Please refresh the page and authenticate again.');
                }
                
                throw new Error(`FHIR API Request failed: HTTP ${response.status} - ${errorText}`);
            }
            
            const data = await response.json();
            console.log('✅ FHIR data retrieved successfully:', data);
            
            return this.parseFHIRMedicationData(data);
            
        } catch (error) {
            console.error('❌ Failed to fetch medications from Epic FHIR:', error);
            throw error;
        }
    }

    // Enhanced patient data retrieval
    async getPatientById(patientId = null) {
        try {
            const pid = patientId || this.patientId;
            const validatedPid = this.validatePatientId(pid);
            
            console.log(`🔍 Retrieving patient data for: ${validatedPid}`);
            
            const data = await this.makeRequest(`Patient/${validatedPid}`);
            console.log('✅ Patient data retrieved successfully');
            return { success: true, data: data };
            
        } catch (error) {
            console.error('❌ Failed to fetch patient from Epic FHIR:', error.message);
            return { success: false, error: error.message, data: null };
        }
    }

    // Enhanced medication parsing with comprehensive validation
    parseMedicationRequests(fhirBundle) {
        if (!fhirBundle || !fhirBundle.entry) {
            console.warn('⚠️ Empty or invalid FHIR bundle received');
            return [];
        }

        const medications = [];
        const errors = [];

        fhirBundle.entry.forEach((entry, index) => {
            try {
            const medicationRequest = entry.resource;
                
                if (!medicationRequest || medicationRequest.resourceType !== 'MedicationRequest') {
                    throw new Error(`Invalid resource type at index ${index}`);
                }

            const medication = this.extractMedicationInfo(medicationRequest);
            
                if (!medication.display || medication.display.trim() === '') {
                    throw new Error(`Missing medication name at index ${index}`);
                }

                const parsedMedication = {
                    id: this.sanitizeHtml(medicationRequest.id || `med-${Date.now()}-${index}`),
                    medicationName: this.sanitizeHtml(medication.display),
                    dosage: this.sanitizeHtml(this.extractDosage(medicationRequest)),
                frequency: this.extractFrequency(medicationRequest),
                times: this.extractTimes(medicationRequest),
                startDate: this.extractStartDate(medicationRequest),
                endDate: this.extractEndDate(medicationRequest),
                foodInstructions: this.extractFoodInstructions(medicationRequest),
                    specialInstructions: this.sanitizeHtml(this.extractInstructions(medicationRequest)),
                reminderTime: CONFIG.APP.DEFAULT_REMINDER_TIME, // Default from config
                color: this.assignColor(medication.display),
                active: medicationRequest.status === 'active',
                    fhirData: medicationRequest,
                    importedAt: new Date().toISOString(),
                    source: this.demoMode ? 'demo' : 'epic-fhir'
                };

                // Validate required fields
                if (!parsedMedication.medicationName || !parsedMedication.dosage) {
                    throw new Error(`Missing required medication data at index ${index}`);
                }

                medications.push(parsedMedication);
                console.log(`✅ Successfully parsed: ${parsedMedication.medicationName}`);

            } catch (error) {
                console.error(`❌ Error parsing medication at index ${index}:`, error.message);
                errors.push({ index, error: error.message });
            }
        });

        if (errors.length > 0) {
            console.warn(`⚠️ ${errors.length} medications could not be parsed:`, errors);
        }

        console.log(`✅ Successfully parsed ${medications.length} out of ${fhirBundle.entry.length} medications`);
        return medications;
    }

    extractMedicationInfo(medicationRequest) {
        if (medicationRequest.medicationCodeableConcept) {
            const coding = medicationRequest.medicationCodeableConcept.coding?.[0];
            return {
                display: coding?.display || medicationRequest.medicationCodeableConcept.text || 'Unknown',
                code: coding?.code,
                system: coding?.system
            };
        }
        return { display: 'Unknown Medication' };
    }

    extractDosage(medicationRequest) {
        const dosageInstruction = medicationRequest.dosageInstruction?.[0];
        if (dosageInstruction?.doseAndRate?.[0]?.doseQuantity) {
            const dose = dosageInstruction.doseAndRate[0].doseQuantity;
            return `${dose.value}${dose.unit || dose.code || ''}`;
        }
        return dosageInstruction?.text || '1 tablet';
    }

    extractFrequency(medicationRequest) {
        const dosageInstruction = medicationRequest.dosageInstruction?.[0];
        if (dosageInstruction?.timing?.repeat) {
            const repeat = dosageInstruction.timing.repeat;
            if (repeat.frequency && repeat.period) {
                const freq = repeat.frequency;
                const period = repeat.period;
                const periodUnit = repeat.periodUnit;
                
                if (freq === 1 && period === 1 && periodUnit === 'd') return 'once-daily';
                if (freq === 2 && period === 1 && periodUnit === 'd') return 'twice-daily';
                if (freq === 3 && period === 1 && periodUnit === 'd') return 'three-times-daily';
                if (freq === 4 && period === 1 && periodUnit === 'd') return 'four-times-daily';
            }
        }
        return 'once-daily';
    }

    extractTimes(medicationRequest) {
        const dosageInstruction = medicationRequest.dosageInstruction?.[0];
        if (dosageInstruction?.timing?.repeat?.timeOfDay) {
            return dosageInstruction.timing.repeat.timeOfDay;
        }
        
        // Default times based on frequency
        const frequency = this.extractFrequency(medicationRequest);
        const defaultTimes = {
            'once-daily': ['08:00'],
            'twice-daily': ['08:00', '20:00'],
            'three-times-daily': ['08:00', '14:00', '20:00'],
            'four-times-daily': ['08:00', '12:00', '16:00', '20:00']
        };
        
        return defaultTimes[frequency] || ['08:00'];
    }

    extractStartDate(medicationRequest) {
        if (medicationRequest.dosageInstruction?.[0]?.timing?.repeat?.boundsPeriod?.start) {
            return medicationRequest.dosageInstruction[0].timing.repeat.boundsPeriod.start.split('T')[0];
        }
        if (medicationRequest.dispenseRequest?.validityPeriod?.start) {
            return medicationRequest.dispenseRequest.validityPeriod.start.split('T')[0];
        }
        return new Date().toISOString().split('T')[0];
    }

    extractEndDate(medicationRequest) {
        if (medicationRequest.dosageInstruction?.[0]?.timing?.repeat?.boundsPeriod?.end) {
            return medicationRequest.dosageInstruction[0].timing.repeat.boundsPeriod.end.split('T')[0];
        }
        if (medicationRequest.dispenseRequest?.validityPeriod?.end) {
            return medicationRequest.dispenseRequest.validityPeriod.end.split('T')[0];
        }
        return null;
    }

    extractFoodInstructions(medicationRequest) {
        const instructions = medicationRequest.dosageInstruction?.[0]?.additionalInstruction;
        if (instructions) {
            const instructionText = instructions[0]?.text?.toLowerCase() || '';
            if (instructionText.includes('with food') || instructionText.includes('with meal')) return 'with-food';
            if (instructionText.includes('without food') || instructionText.includes('empty stomach')) return 'without-food';
            if (instructionText.includes('before meal')) return 'before-meals';
            if (instructionText.includes('after meal')) return 'after-meals';
        }
        return 'no-restriction';
    }

    extractInstructions(medicationRequest) {
        const patientInstruction = medicationRequest.dosageInstruction?.[0]?.patientInstruction;
        const additionalInstruction = medicationRequest.dosageInstruction?.[0]?.additionalInstruction?.[0]?.text;
        return patientInstruction || additionalInstruction || '';
    }

    assignColor(medicationName) {
        // Simple color assignment based on medication name
        const colors = ['blue', 'green', 'red', 'purple', 'orange', 'pink'];
        const hash = medicationName.split('').reduce((a, b) => {
            a = ((a << 5) - a) + b.charCodeAt(0);
            return a & a;
        }, 0);
        return colors[Math.abs(hash) % colors.length];
    }

    async createMedicationRequest(prescriptionData) {
        // Convert app prescription format to FHIR MedicationRequest
        const fhirMedicationRequest = {
            resourceType: 'MedicationRequest',
            status: 'active',
            intent: 'order',
            subject: {
                reference: `Patient/${this.patientId}`
            },
            medicationCodeableConcept: {
                text: prescriptionData.medicationName,
                coding: [{
                    display: prescriptionData.medicationName
                }]
            },
            dosageInstruction: [{
                text: `Take ${prescriptionData.dosage} ${prescriptionData.frequency.replace('-', ' ')}`,
                timing: {
                    repeat: this.convertFrequencyToFHIR(prescriptionData.frequency),
                    timeOfDay: prescriptionData.times
                },
                doseAndRate: [{
                    doseQuantity: this.parseDosageToQuantity(prescriptionData.dosage)
                }],
                additionalInstruction: prescriptionData.specialInstructions ? [{
                    text: prescriptionData.specialInstructions
                }] : undefined
            }]
        };

        try {
            // In a real implementation, you'd POST this to the FHIR server
            // For now, we'll just log it and return success
            console.log('Would create FHIR MedicationRequest:', fhirMedicationRequest);
            return { success: true, id: `epic-${Date.now()}` };
        } catch (error) {
            console.error('Failed to create medication request:', error);
            throw error;
        }
    }

    convertFrequencyToFHIR(frequency) {
        const frequencyMap = {
            'once-daily': { frequency: 1, period: 1, periodUnit: 'd' },
            'twice-daily': { frequency: 2, period: 1, periodUnit: 'd' },
            'three-times-daily': { frequency: 3, period: 1, periodUnit: 'd' },
            'four-times-daily': { frequency: 4, period: 1, periodUnit: 'd' },
            'weekly': { frequency: 1, period: 1, periodUnit: 'wk' }
        };
        return frequencyMap[frequency] || frequencyMap['once-daily'];
    }

    parseDosageToQuantity(dosageString) {
        const match = dosageString.match(/(\d+(?:\.\d+)?)\s*(\w+)?/);
        if (match) {
            return {
                value: parseFloat(match[1]),
                unit: match[2] || 'tablet',
                system: 'http://unitsofmeasure.org'
            };
        }
        return { value: 1, unit: 'tablet' };
    }

    // Parse FHIR medication data into application format
    parseFHIRMedicationData(fhirBundle) {
        try {
            if (!fhirBundle || !fhirBundle.entry) {
                console.log('ℹ️ No medication entries found in FHIR bundle');
                return [];
            }

            console.log(`🔄 Parsing ${fhirBundle.entry.length} FHIR medication entries...`);
            
            const medications = [];
            
            for (const entry of fhirBundle.entry) {
                try {
                    const medicationRequest = entry.resource;
                    
                    if (medicationRequest.resourceType !== 'MedicationRequest') {
                        console.warn('⚠️ Skipping non-MedicationRequest resource:', medicationRequest.resourceType);
                        continue;
                    }
                    
                    // Skip inactive medications
                    if (medicationRequest.status !== 'active') {
                        console.log(`ℹ️ Skipping inactive medication: ${medicationRequest.status}`);
                        continue;
                    }
                    
                    const medication = this.parseMedicationRequest(medicationRequest);
                    if (medication) {
                        medications.push(medication);
                    }
                    
                } catch (error) {
                    console.error('❌ Error parsing individual medication entry:', error);
                    // Continue processing other medications
                }
            }
            
            console.log(`✅ Successfully parsed ${medications.length} medications from FHIR data`);
            return medications;
            
        } catch (error) {
            console.error('❌ Error parsing FHIR medication data:', error);
            throw new Error(`Failed to parse FHIR medication data: ${error.message}`);
        }
    }

    // Parse individual MedicationRequest into application format
    parseMedicationRequest(medicationRequest) {
        try {
            // Extract medication name
            const medicationName = this.extractMedicationInfo(medicationRequest);
            if (!medicationName) {
                console.warn('⚠️ Skipping medication without name');
                return null;
            }
            
            // Extract dosage information
            const dosage = this.extractDosage(medicationRequest);
            const frequency = this.extractFrequency(medicationRequest);
            const times = this.extractTimes(medicationRequest);
            
            // Extract dates
            const startDate = this.extractStartDate(medicationRequest);
            const endDate = this.extractEndDate(medicationRequest);
            
            // Extract instructions
            const foodInstructions = this.extractFoodInstructions(medicationRequest);
            const specialInstructions = this.extractInstructions(medicationRequest);
            
            // Create medication object in application format
            const medication = {
                id: medicationRequest.id || `fhir-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                medicationName: medicationName,
                dosage: dosage || '1 unit',
                frequency: frequency || 'once-daily',
                times: times.length > 0 ? times : ['08:00'],
                startDate: startDate || this.formatDate(new Date()),
                endDate: endDate,
                foodInstructions: foodInstructions || 'no-restriction',
                specialInstructions: specialInstructions || '',
                reminderTime: CONFIG.APP.DEFAULT_REMINDER_TIME, // Default from config
                color: this.assignColor(medicationName),
                active: true,
                source: 'epic-fhir', // Mark as imported from Epic FHIR
                importedAt: new Date().toISOString(),
                fhirData: medicationRequest // Store original FHIR data for reference
            };
            
            console.log(`✅ Parsed medication: ${medicationName} (${dosage}, ${frequency})`);
            return medication;
            
        } catch (error) {
            console.error('❌ Error parsing medication request:', error);
            return null;
        }
    }

    // Helper method to format dates consistently
    formatDate(date) {
        if (!date) return null;
        if (typeof date === 'string') return date;
        
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        
        return `${year}-${month}-${day}`;
    }
}

// Resend Client for Email Reminders
class ResendClient {
    constructor() {
        // Check if CONFIG is available
        if (typeof CONFIG === 'undefined') {
            console.error('❌ Configuration not loaded. Please ensure config.js is included before script.js');
            throw new Error('Configuration not available. Please check config.js file.');
        }

        // Use configuration from config.js
        const resendConfig = CONFIG.RESEND;
        
        this.apiKey = resendConfig.API_KEY;
        this.baseUrl = resendConfig.BASE_URL;
        this.fromEmail = resendConfig.FROM_EMAIL;
        
        // Check if API key looks like a placeholder
        if (this.apiKey.includes('YOUR_RESEND') || this.apiKey === 'YOUR_RESEND_API_KEY_HERE') {
            console.warn('⚠️ Resend API key not configured. Email reminders will run in demo mode.');
            this.isConfigured = false;
            this.demoMode = true;
        } else {
            this.isConfigured = true;
            this.demoMode = false;
        }
    }

    async sendEmail(to, subject, html, text = null) {
        if (!this.isConfigured) {
            // Demo mode - simulate sending email
            if (this.demoMode) {
                console.log('📧 DEMO MODE - Email would be sent:');
                console.log(`To: ${to}`);
                console.log(`Subject: ${subject}`);
                console.log(`Content: ${text || 'HTML email content'}`);
                
                // Simulate API delay
                await new Promise(resolve => setTimeout(resolve, 500));
                
                return {
                    id: `demo_${Date.now()}`,
                    message: 'Demo email sent successfully'
                };
            } else {
                throw new Error('Resend API not configured. Please update the API key and from email in the ResendClient constructor.');
            }
        }

        try {
            console.log('Attempting to send email via Resend API...');
            
            const response = await fetch(`${this.baseUrl}/emails`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    from: this.fromEmail,
                    to: [to],
                    subject: subject,
                    html: html,
                    text: text
                })
            });

            const responseData = await response.json();
            
            if (!response.ok) {
                console.error('Resend API Error Response:', responseData);
                throw new Error(`Resend API error: ${response.status} - ${responseData.message || 'Unknown error'}`);
            }

            console.log('Email sent successfully:', responseData.id);
            return responseData;
        } catch (error) {
            console.error('Failed to send email:', error);
            
            // Provide helpful error messages
            if (error.message.includes('401')) {
                throw new Error('Invalid Resend API key. Please check your API key configuration.');
            } else if (error.message.includes('403')) {
                throw new Error('Resend API access denied. Please verify your domain and API key.');
            } else if (error.message.includes('422')) {
                throw new Error('Invalid email format or unverified domain. Please check your from email address.');
            } else {
                throw error;
            }
        }
    }

    async sendReminderEmail(userEmail, medicationName, dosage, time, instructions = '') {
        const subject = `💊 Medication Reminder: ${medicationName}`;
        
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Medication Reminder</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background-color: #f5f7fa; }
                    .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center; }
                    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
                    .content { padding: 30px 20px; }
                    .medication-card { background-color: #f8fafc; border-left: 4px solid #667eea; padding: 20px; border-radius: 4px; margin: 20px 0; }
                    .medication-name { font-size: 20px; font-weight: 600; color: #2d3748; margin-bottom: 10px; }
                    .dosage { font-size: 16px; color: #4a5568; margin-bottom: 5px; }
                    .time { font-size: 16px; color: #667eea; font-weight: 500; margin-bottom: 10px; }
                    .instructions { font-size: 14px; color: #718096; font-style: italic; }
                    .footer { background-color: #f8fafc; padding: 20px; text-align: center; color: #718096; font-size: 12px; }
                    .reminder-icon { font-size: 48px; margin-bottom: 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="reminder-icon">💊</div>
                        <h1>Medication Reminder</h1>
                    </div>
                    <div class="content">
                        <p>It's time to take your medication!</p>
                        <div class="medication-card">
                            <div class="medication-name">${medicationName}</div>
                            <div class="dosage">Dosage: ${dosage}</div>
                            <div class="time">⏰ Time: ${time}</div>
                            ${instructions ? `<div class="instructions">${instructions}</div>` : ''}
                        </div>
                        <p>Please take your medication as prescribed. If you have any questions, consult with your healthcare provider.</p>
                    </div>
                    <div class="footer">
                        <p>This is an automated reminder from MediCal. Please do not reply to this email.</p>
                    </div>
                </div>
            </body>
            </html>
        `;

        const text = `
Medication Reminder: ${medicationName}

It's time to take your medication!

Medication: ${medicationName}
Dosage: ${dosage}
Time: ${time}
${instructions ? `Instructions: ${instructions}` : ''}

Please take your medication as prescribed. If you have any questions, consult with your healthcare provider.

This is an automated reminder from MediCal.
        `;

        return await this.sendEmail(userEmail, subject, html, text);
    }

    async sendDailySummaryEmail(userEmail, todaysMedications) {
        const subject = `📅 Daily Medication Summary - ${new Date().toLocaleDateString()}`;
        
        let medicationList = '';
        todaysMedications.forEach(med => {
            medicationList += `
                <div class="medication-item">
                    <div class="med-name">${med.medicationName}</div>
                    <div class="med-details">${med.dosage} at ${med.times.join(', ')}</div>
                    ${med.specialInstructions ? `<div class="med-instructions">${med.specialInstructions}</div>` : ''}
                </div>
            `;
        });

        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Daily Medication Summary</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background-color: #f5f7fa; }
                    .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center; }
                    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
                    .content { padding: 30px 20px; }
                    .medication-item { background-color: #f8fafc; border-left: 4px solid #667eea; padding: 15px; border-radius: 4px; margin: 15px 0; }
                    .med-name { font-size: 18px; font-weight: 600; color: #2d3748; margin-bottom: 5px; }
                    .med-details { font-size: 14px; color: #4a5568; margin-bottom: 5px; }
                    .med-instructions { font-size: 12px; color: #718096; font-style: italic; }
                    .footer { background-color: #f8fafc; padding: 20px; text-align: center; color: #718096; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>📅 Daily Medication Summary</h1>
                        <p>${new Date().toLocaleDateString()}</p>
                    </div>
                    <div class="content">
                        <p>Here are your medications scheduled for today:</p>
                        ${medicationList}
                        <p>Remember to take your medications as prescribed. Have a healthy day!</p>
                    </div>
                    <div class="footer">
                        <p>This is an automated summary from MediCal. Please do not reply to this email.</p>
                    </div>
                </div>
            </body>
            </html>
        `;

        return await this.sendEmail(userEmail, subject, html);
    }
}

class PrescriptionReminderApp {
    constructor() {
        this.currentDate = new Date();
        this.currentView = 'day';
        this.prescriptions = [];
        this.scheduledReminders = [];
        this.doseHistory = [];
        this.settings = {};
        this.fhirClient = new EpicFHIRClient();
        this.resendClient = new ResendClient();
        
        this.init();
    }

    // ========================================================================
    // MAIN APPLICATION INITIALIZATION
    // ========================================================================
    
    async init() {
        try {
            // Initialize security monitoring
            this.monitorSecurityEvents();
            
            // Perform system health check
            const healthStatus = this.performHealthCheck();
            if (!healthStatus.localStorage) {
                throw new Error('localStorage not available - data cannot be saved');
            }
            
            // Create initial backup
            this.createDataBackup('initialization');
            
            this.loadData();
            this.setupEventListeners();
            
            // Check if we're returning from Epic OAuth
            const urlParams = new URLSearchParams(window.location.search);
            const authCode = urlParams.get('code');
            const state = urlParams.get('state');
            const error = urlParams.get('error');
            
            if (error) {
                console.error('❌ OAuth error:', error, urlParams.get('error_description'));
                this.showNotification(`❌ Authentication failed: ${error}`, 'error');
                // Clean up URL
                window.history.replaceState({}, document.title, window.location.pathname);
            } else if (authCode && state) {
                console.log('🔄 Processing OAuth callback...');
                this.showNotification('🔐 Processing authentication...', 'info');
                
                try {
                    const result = await this.fhirClient.handleOAuthCallback(authCode, state);
                    if (result.success) {
                        console.log('✅ Authentication successful!');
                        this.showNotification('✅ Authentication successful! Loading medications...', 'success');
                        
                        // Clean up URL
                        window.history.replaceState({}, document.title, window.location.pathname);
                        
                        // Load FHIR data
                        await this.loadFHIRData();
                        this.renderCalendar();
                        this.renderPrescriptionList();
                        this.scheduleAllReminders();
                        
                        console.log('✅ Epic FHIR integration completed successfully');
                        return;
                    }
                } catch (error) {
                    console.error('❌ OAuth callback failed:', error);
                    this.showNotification(`❌ Authentication failed: ${error.message}`, 'error');
                    // Clean up URL
                    window.history.replaceState({}, document.title, window.location.pathname);
                }
            }
            
            // Normal initialization flow
            await this.loadFHIRData();
            
            // Clean up any duplicate prescriptions from previous bugs
            this.cleanupDuplicatePrescriptions();
            
            // Ensure view buttons are properly synchronized
            this.initializeViewSelector();
        
        this.renderCalendar();
        this.renderPrescriptionList();
        this.scheduleAllReminders();
        
            // Update reminder status on startup
            this.updateReminderStats();
            
            // Make cleanup and debugging functions available in console
            window.cleanupDuplicates = () => this.cleanupDuplicatePrescriptions();
            window.performHealthCheck = () => this.performHealthCheck();
            window.createBackup = () => this.createDataBackup('manual');
            window.recoverFromBackup = () => this.recoverFromBackup();
            
            console.log('✅ Prescription Reminder System initialized successfully with Epic FHIR integration');
            console.log('🔒 Security monitoring active');
            console.log('💡 Debug commands available: cleanupDuplicates(), performHealthCheck(), createBackup(), recoverFromBackup()');
            console.log('💡 Type "testEmailSetup()" to check email configuration');
            console.log('💡 Type "testFHIRSetup()" to check Epic FHIR configuration');
            
            // Show initialization success
            this.showNotification('✅ MediCal system ready! Your medication data is secure.', 'success');
            
        } catch (error) {
            this.handleError(error, 'initialization', true);
            
            // Try to recover from backup if initialization fails
            console.log('🔄 Attempting to recover from backup...');
            const recovered = this.recoverFromBackup();
            
            if (!recovered) {
                // Last resort - load with minimal functionality
                console.log('⚠️ Loading with minimal functionality...');
                this.prescriptions = [];
                this.doseHistory = [];
                this.settings = {
                    epicPatientId: '',
                    useEpicFHIR: false,
                    email: '',
                    enableEmailReminders: false,
                    enableDailySummary: false,
                    dailySummaryTime: '08:00'
                };
                
                this.setupEventListeners();
                this.loadMockFHIRData();
                this.renderCalendar();
                this.renderPrescriptionList();
                
                this.showNotification('⚠️ System started with limited functionality. Some features may not work.', 'warning');
            }
        }
    }

    loadData() {
        // Load from localStorage
        this.prescriptions = JSON.parse(localStorage.getItem('prescriptions') || '[]');
        this.doseHistory = JSON.parse(localStorage.getItem('doseHistory') || '[]');
        this.settings = JSON.parse(localStorage.getItem('settings') || '{}');
        
        // Set default settings
        this.settings = {
            // Epic FHIR settings - only need patient ID from user
            epicPatientId: '',
            useEpicFHIR: false,
            // Email settings
            email: '',
            enableEmailReminders: true,
            enableDailySummary: false,
            dailySummaryTime: '08:00',
            ...this.settings
        };
    }

    saveData() {
        localStorage.setItem('prescriptions', JSON.stringify(this.prescriptions));
        localStorage.setItem('doseHistory', JSON.stringify(this.doseHistory));
        localStorage.setItem('settings', JSON.stringify(this.settings));
    }

    // ========================================================================
    // EPIC FHIR INTEGRATION
    // ========================================================================
    
    async loadFHIRData() {
        if (this.settings.useEpicFHIR) {
            try {
                this.showNotification('🔄 Connecting to Epic FHIR...', 'info');
                
                // Validate patient ID before attempting connection
                if (this.settings.epicPatientId) {
                    try {
                        this.fhirClient.validatePatientId(this.settings.epicPatientId);
                    } catch (error) {
                        this.showNotification(`❌ Invalid Patient ID: ${error.message}`, 'error');
                        return;
                    }
                }
                
                const initResult = await this.fhirClient.initialize(this.settings.epicPatientId);
                
                if (!initResult.success) {
                    throw new Error(initResult.error);
                }
                
                // Create comprehensive backup before any changes
                const backupData = {
                    prescriptions: [...this.prescriptions],
                    doseHistory: [...this.doseHistory],
                    settings: { ...this.settings },
                    timestamp: new Date().toISOString(),
                    source: 'pre-fhir-import',
                    patientId: this.settings.epicPatientId || 'demo'
                };
                localStorage.setItem('prescriptions_backup', JSON.stringify(backupData));
                console.log('✅ Created comprehensive backup before FHIR import');
                
                const medicationResult = await this.fhirClient.getPatientMedicationRequests();
                
                if (!medicationResult.success) {
                    throw new Error(medicationResult.error);
                }
                
                if (medicationResult.data && medicationResult.data.length > 0) {
                    // Validate imported medications before replacing
                    const validatedMedications = this.validateImportedMedications(medicationResult.data);
                    
                    if (validatedMedications.length === 0) {
                        this.showNotification('⚠️ No valid medications found in FHIR data', 'warning');
                        return;
                    }
                    
                    // SECURE MEDICATION REPLACEMENT LOGIC
                    const replacementResult = await this.securelyReplaceMedications(validatedMedications);
                    
                    if (replacementResult.success) {
                        this.saveData();
                        
                        const modeText = this.fhirClient.demoMode ? ' (Demo Mode)' : '';
                        const message = `✅ Successfully imported ${replacementResult.imported} medications from Epic FHIR${modeText}`;
                        
                        if (replacementResult.replaced > 0) {
                            this.showNotification(`${message}. Replaced ${replacementResult.replaced} existing medications.`, 'success');
                        } else {
                            this.showNotification(message, 'success');
                        }
                        
                        // Log detailed replacement results
                        console.log('📊 FHIR Import & Replacement Results:', {
                            total: medicationResult.data.length,
                            validated: validatedMedications.length,
                            imported: replacementResult.imported,
                            replaced: replacementResult.replaced,
                            preserved: replacementResult.preserved,
                            backupCreated: true
                        });
                        
                        // Clear any existing reminders and reschedule with new medications
                        this.scheduleAllReminders();
                        
                        return;
                    } else {
                        throw new Error(replacementResult.error);
                    }
                } else {
                    this.showNotification('ℹ️ No active medications found in Epic FHIR', 'info');
                }
                
            } catch (error) {
                console.error('❌ Epic FHIR integration failed:', error);
                
                // Provide specific error messages based on error type
                if (error.message.includes('Patient ID')) {
                    this.showNotification('❌ Invalid Patient ID format. Please check your Patient ID in settings.', 'error');
                } else if (error.message.includes('not configured')) {
                    this.showNotification('⚠️ Epic FHIR API not configured (see console for setup)', 'warning');
                } else if (error.message.includes('Connection test failed')) {
                    this.showNotification('❌ Cannot connect to Epic FHIR servers. Please check your internet connection.', 'error');
                } else if (error.message.includes('401') || error.message.includes('403')) {
                    this.showNotification('❌ Authentication failed. Please check your Epic FHIR credentials.', 'error');
                } else if (error.message.includes('404')) {
                    this.showNotification('❌ Patient not found. Please verify the Patient ID is correct.', 'error');
                } else {
                    this.showNotification('❌ Epic FHIR connection failed. Check console for details.', 'error');
                }
                
                // Restore from backup if import failed
                this.restoreFromBackup();
            }
        }
        
        // Fallback to mock data if no FHIR connection or no existing data
        if (this.prescriptions.length === 0) {
            this.loadMockFHIRData();
        }
    }

    // Secure medication replacement with comprehensive safety checks
    async securelyReplaceMedications(newMedications) {
        try {
            console.log('🔄 Starting secure medication replacement process...');
            
            // Step 1: Analyze existing medications
            const existingMedications = [...this.prescriptions];
            const existingCount = existingMedications.length;
            
            // Step 2: Categorize existing medications
            const fhirMedications = existingMedications.filter(med => med.source === 'epic-fhir' || med.source === 'demo');
            const manualMedications = existingMedications.filter(med => !med.source || med.source === 'manual');
            
            console.log(`📊 Medication Analysis:
                - Total existing: ${existingCount}
                - FHIR/Demo medications: ${fhirMedications.length}
                - Manual medications: ${manualMedications.length}
                - New FHIR medications: ${newMedications.length}`);
            
            // Step 3: Create replacement strategy
            let replacementStrategy = 'merge'; // Default strategy
            
            if (this.settings.epicPatientId && this.settings.epicPatientId.trim() !== '') {
                // Real Patient ID provided - replace FHIR/demo medications, keep manual ones
                replacementStrategy = 'replace-fhir-keep-manual';
            } else {
                // Demo mode - replace all with demo data
                replacementStrategy = 'replace-all-demo';
            }
            
            console.log(`🎯 Replacement strategy: ${replacementStrategy}`);
            
            // Step 4: Execute replacement based on strategy
            let newPrescriptionList = [];
            let replaced = 0;
            let preserved = 0;
            
            switch (replacementStrategy) {
                case 'replace-fhir-keep-manual':
                    // Keep manually added medications, replace FHIR/demo ones
                    newPrescriptionList = [...manualMedications, ...newMedications];
                    replaced = fhirMedications.length;
                    preserved = manualMedications.length;
                    
                    console.log(`✅ Keeping ${preserved} manual medications, replacing ${replaced} FHIR/demo medications`);
                    break;
                    
                case 'replace-all-demo':
                    // Demo mode - replace everything with new demo data
                    newPrescriptionList = [...newMedications];
                    replaced = existingCount;
                    preserved = 0;
                    
                    console.log(`🧪 Demo mode: Replacing all ${replaced} medications with demo data`);
                    break;
                    
                default:
                    // Fallback - merge without duplicates
                    newPrescriptionList = this.mergeMedicationsSafely(existingMedications, newMedications);
                    replaced = 0;
                    preserved = existingCount;
                    
                    console.log(`🔄 Fallback: Merging medications safely`);
                    break;
            }
            
            // Step 5: Validate the new medication list
            const validationResult = this.validateMedicationList(newPrescriptionList);
            if (!validationResult.valid) {
                throw new Error(`Medication list validation failed: ${validationResult.error}`);
            }
            
            // Step 6: Preserve dose history for medications that are being kept
            const preservedDoseHistory = this.preserveRelevantDoseHistory(newPrescriptionList);
            
            // Step 7: Apply the changes
            this.prescriptions = newPrescriptionList;
            this.doseHistory = preservedDoseHistory;
            
            console.log(`✅ Medication replacement completed successfully:
                - New total: ${this.prescriptions.length}
                - Replaced: ${replaced}
                - Preserved: ${preserved}
                - Dose history entries preserved: ${preservedDoseHistory.length}`);
            
            return {
                success: true,
                imported: newMedications.length,
                replaced: replaced,
                preserved: preserved,
                total: this.prescriptions.length
            };
            
        } catch (error) {
            console.error('❌ Secure medication replacement failed:', error);
            return {
                success: false,
                error: error.message,
                imported: 0,
                replaced: 0,
                preserved: 0
            };
        }
    }

    // Safely merge medications without duplicates
    mergeMedicationsSafely(existingMedications, newMedications) {
        const mergedList = [...existingMedications];
        let addedCount = 0;
        
        newMedications.forEach(newMed => {
            // Check for duplicates based on medication name and dosage
            const isDuplicate = existingMedications.some(existingMed => 
                existingMed.medicationName.toLowerCase() === newMed.medicationName.toLowerCase() &&
                existingMed.dosage.toLowerCase() === newMed.dosage.toLowerCase()
            );
            
            if (!isDuplicate) {
                mergedList.push(newMed);
                addedCount++;
                console.log(`✅ Added new medication: ${newMed.medicationName} ${newMed.dosage}`);
            } else {
                console.log(`⚠️ Skipped duplicate: ${newMed.medicationName} ${newMed.dosage}`);
            }
        });
        
        console.log(`🔄 Merge completed: ${addedCount} new medications added`);
        return mergedList;
    }

    // Validate the entire medication list for consistency and safety
    validateMedicationList(medications) {
        try {
            if (!Array.isArray(medications)) {
                return { valid: false, error: 'Medication list must be an array' };
            }
            
            if (medications.length === 0) {
                return { valid: true }; // Empty list is valid
            }
            
            // Check for required fields in each medication
            for (let i = 0; i < medications.length; i++) {
                const med = medications[i];
                
                if (!med.id || !med.medicationName || !med.dosage || !med.frequency || !Array.isArray(med.times)) {
                    return { valid: false, error: `Medication at index ${i} is missing required fields` };
                }
                
                // Check for duplicate IDs
                const duplicateId = medications.find((otherMed, otherIndex) => 
                    otherIndex !== i && otherMed.id === med.id
                );
                
                if (duplicateId) {
                    return { valid: false, error: `Duplicate medication ID found: ${med.id}` };
                }
            }
            
            console.log(`✅ Medication list validation passed: ${medications.length} medications`);
            return { valid: true };
            
        } catch (error) {
            return { valid: false, error: error.message };
        }
    }

    // Preserve dose history for medications that are being kept
    preserveRelevantDoseHistory(newMedicationList) {
        const medicationIds = new Set(newMedicationList.map(med => med.id));
        const preservedHistory = this.doseHistory.filter(doseRecord => {
            // Keep dose history for medications that still exist
            return medicationIds.has(doseRecord.prescriptionId);
        });
        
        console.log(`📊 Dose history: ${this.doseHistory.length} total, ${preservedHistory.length} preserved`);
        return preservedHistory;
    }

    // Enhanced backup restoration with medication replacement awareness
    restoreFromBackup() {
        try {
            const backupData = localStorage.getItem('prescriptions_backup');
            if (backupData) {
                const backup = JSON.parse(backupData);
                
                // Restore all data from backup
                this.prescriptions = backup.data.prescriptions || backup.prescriptions || [];
                this.doseHistory = backup.data.doseHistory || backup.doseHistory || [];
                
                // Restore settings but keep current patient ID for security
                const currentPatientId = this.settings.epicPatientId;
                if (backup.data && backup.data.settings) {
                    this.settings = { ...backup.data.settings, epicPatientId: currentPatientId };
                } else if (backup.settings) {
                    this.settings = { ...backup.settings, epicPatientId: currentPatientId };
                }
                
                this.saveData();
                this.renderCalendar();
                this.renderPrescriptionList();
                
                console.log('✅ Data restored from backup after failed medication replacement');
                this.showNotification('🔄 Restored previous medication data after import failure', 'info');
                return true;
            } else {
                console.warn('⚠️ No backup available for restoration');
            return false;
            }
        } catch (error) {
            console.error('❌ Failed to restore from backup:', error);
            this.showNotification('❌ Failed to restore from backup', 'error');
            return false;
        }
    }

    // Validate imported medications for security and data integrity
    validateImportedMedications(medications) {
        const validMedications = [];
        const errors = [];

        medications.forEach((med, index) => {
            try {
                // Required field validation
                if (!med.medicationName || med.medicationName.trim() === '') {
                    throw new Error('Missing medication name');
                }
                
                if (!med.dosage || med.dosage.trim() === '') {
                    throw new Error('Missing dosage information');
                }
                
                if (!med.frequency) {
                    throw new Error('Missing frequency information');
                }
                
                if (!Array.isArray(med.times) || med.times.length === 0) {
                    throw new Error('Missing or invalid time information');
                }
                
                // Validate medication name (no suspicious content)
                if (med.medicationName.length > 100) {
                    throw new Error('Medication name too long');
                }
                
                // Validate dosage format
                if (med.dosage.length > 50) {
                    throw new Error('Dosage information too long');
                }
                
                // Validate times format
                const timePattern = /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/;
                for (const time of med.times) {
                    if (!timePattern.test(time)) {
                        throw new Error(`Invalid time format: ${time}`);
                    }
                }
                
                // Validate dates if present
                if (med.startDate && !this.isValidDate(med.startDate)) {
                    throw new Error('Invalid start date');
                }
                
                if (med.endDate && !this.isValidDate(med.endDate)) {
                    throw new Error('Invalid end date');
                }
                
                // Ensure required fields are present and properly formatted
                const validatedMed = {
                    ...med,
                    id: med.id || `fhir-${Date.now()}-${index}`,
                    medicationName: med.medicationName.trim(),
                    dosage: med.dosage.trim(),
                    specialInstructions: (med.specialInstructions || '').trim(),
                    reminderTime: Math.max(5, Math.min(120, med.reminderTime || 30)), // Clamp between 5-120 minutes
                    active: med.active !== false, // Default to true
                    importedAt: new Date().toISOString(),
                    validated: true
                };
                
                validMedications.push(validatedMed);
                console.log(`✅ Validated medication: ${validatedMed.medicationName}`);
                
            } catch (error) {
                console.error(`❌ Validation failed for medication at index ${index}:`, error.message);
                errors.push({ index, medication: med.medicationName || 'Unknown', error: error.message });
            }
        });

        if (errors.length > 0) {
            console.warn(`⚠️ ${errors.length} medications failed validation:`, errors);
            this.showNotification(`⚠️ ${errors.length} medications could not be imported due to validation errors`, 'warning');
        }

        return validMedications;
    }

    // Merge imported medications with existing data, avoiding duplicates
    mergeMedicationData(importedMedications) {
        let imported = 0;
        let duplicates = 0;
        const existing = this.prescriptions.length;

        importedMedications.forEach(importedMed => {
            // Check for duplicates based on medication name and dosage
            const isDuplicate = this.prescriptions.some(existingMed => 
                existingMed.medicationName.toLowerCase() === importedMed.medicationName.toLowerCase() &&
                existingMed.dosage.toLowerCase() === importedMed.dosage.toLowerCase()
            );

            if (isDuplicate) {
                duplicates++;
                console.log(`⚠️ Skipping duplicate: ${importedMed.medicationName} ${importedMed.dosage}`);
            } else {
                this.prescriptions.push(importedMed);
                imported++;
                console.log(`✅ Imported: ${importedMed.medicationName} ${importedMed.dosage}`);
            }
        });

        return { imported, duplicates, existing };
    }

    async connectToEpicFHIR() {
        // Validate patient ID before attempting connection
        if (!this.settings.epicPatientId || this.settings.epicPatientId.trim() === '') {
            this.showNotification('❌ Please enter a Patient ID in settings before connecting to Epic FHIR', 'error');
            return false;
        }

        try {
            this.fhirClient.validatePatientId(this.settings.epicPatientId);
        } catch (error) {
            this.showNotification(`❌ Invalid Patient ID: ${error.message}`, 'error');
            return false;
        }

        if (!this.fhirClient.isConfigured && !this.fhirClient.demoMode) {
            this.showNotification('Epic FHIR API not configured. Please check console for setup instructions.', 'warning');
            console.error(`
🚨 EPIC FHIR SETUP REQUIRED:

1. 📝 Register at https://fhir.epic.com
2. 🔑 Get your Client ID from the Epic developer portal
3. 🌐 Configure your OAuth redirect URI to: ${window.location.origin}${window.location.pathname}
4. ✏️  Edit script.js lines 10-11:

   REPLACE THIS:
   this.clientId = 'YOUR_EPIC_CLIENT_ID_HERE';

   WITH YOUR ACTUAL VALUES:
   this.clientId = 'your_actual_client_id_here';

5. 💾 Save the file and refresh the page

📱 Current Mode: Demo Mode (simulated FHIR data)

🔒 SECURITY NOTE: Never share your Patient ID publicly. This ID should only be used by the patient themselves or their authorized caregivers.

🔧 TROUBLESHOOTING:
- Make sure your Client ID starts with the correct prefix (production IDs start with 'd', non-production with 'c')
- Ensure your redirect URI exactly matches what's configured in Epic
- Check that your Epic app has the required scopes: patient/MedicationRequest.read patient/Patient.read
            `);
            return false;
        }

        // Show clear explanation of what will happen
        const existingMedCount = this.prescriptions.length;
        const manualMedCount = this.prescriptions.filter(med => med.source === 'manual').length;
        const demoMedCount = this.prescriptions.filter(med => med.source === 'demo' || med.source === 'epic-fhir').length;
        
        if (existingMedCount > 0) {
            let explanationMessage = `📋 You currently have ${existingMedCount} medications in the system.\n\n`;
            
            if (manualMedCount > 0 && demoMedCount > 0) {
                explanationMessage += `• ${manualMedCount} manually added medications will be KEPT\n`;
                explanationMessage += `• ${demoMedCount} demo/sample medications will be REPLACED\n\n`;
            } else if (manualMedCount > 0) {
                explanationMessage += `• All ${manualMedCount} manually added medications will be KEPT\n\n`;
            } else {
                explanationMessage += `• All ${demoMedCount} demo medications will be REPLACED\n\n`;
            }
            
            explanationMessage += `Your real medications from Epic FHIR will be imported and added to the system.`;
            
            console.log(explanationMessage);
            this.showNotification('🔄 Importing your medications from Epic FHIR. Check console for details.', 'info');
        }

        try {
            this.showNotification('🔄 Connecting to Epic FHIR...', 'info');
            
            // Initialize FHIR client
            const initResult = await this.fhirClient.initialize(this.settings.epicPatientId);
            
            if (!initResult.success) {
                throw new Error(initResult.error);
            }
            
            if (initResult.mode === 'demo') {
                console.log('🧪 Running in demo mode');
                await this.loadFHIRData();
                this.renderCalendar();
                this.renderPrescriptionList();
                return true;
            }
            
            if (initResult.mode === 'oauth-required') {
                console.log('🔐 OAuth authentication required');
                
                // Try to authenticate
                const authResult = await this.fhirClient.authenticateWithEpic();
                
                if (authResult.success && authResult.mode === 'stored-token') {
                    console.log('✅ Using stored authentication token');
                    this.showNotification('✅ Using stored authentication. Loading medications...', 'success');
                    
                    await this.loadFHIRData();
                    this.renderCalendar();
                    this.renderPrescriptionList();
                    return true;
                } else if (authResult.mode === 'oauth-redirect') {
                    // User will be redirected to Epic for authentication
                    console.log('🚀 Redirecting to Epic for authentication...');
                    this.showNotification('🔐 Redirecting to Epic for secure authentication...', 'info');
                    // The redirect happens in authenticateWithEpic(), so we just wait
                    return false; // Will redirect, so return false for now
                } else {
                    throw new Error('Authentication setup failed');
                }
            }
            
        } catch (error) {
            console.error('❌ Epic FHIR connection failed:', error);
            
            // Provide specific error guidance
            if (error.message.includes('401') || error.message.includes('Unauthorized')) {
                this.showNotification(`❌ Authentication failed. Please check your Client ID and ensure it's properly configured in Epic. ${error.message}`, 'error');
                console.error(`
🔧 AUTHENTICATION TROUBLESHOOTING:

1. ✅ Verify your Client ID is correct
2. ✅ Check that your redirect URI matches exactly: ${window.location.origin}${window.location.pathname}
3. ✅ Ensure your Epic app has the required scopes:
   - patient/MedicationRequest.read
   - patient/Patient.read
4. ✅ Verify the Patient ID format is correct
5. ✅ Make sure you're using the right Epic environment (production vs sandbox)

Current Client ID: ${this.fhirClient.clientId}
Current Redirect URI: ${this.fhirClient.redirectUri}
                `);
            } else {
                this.showNotification(`❌ Failed to connect to Epic FHIR: ${error.message}`, 'error');
            }
        }
        
        return false;
    }

    async syncWithEpicFHIR() {
        if (!this.settings.useEpicFHIR) {
            this.showNotification('❌ Epic FHIR integration is disabled in settings', 'warning');
            return;
        }

        if (!this.settings.epicPatientId || this.settings.epicPatientId.trim() === '') {
            this.showNotification('❌ Please enter a Patient ID in settings before syncing', 'error');
            return;
        }

        // Show clear explanation before sync
        const existingMedCount = this.prescriptions.length;
        const manualMedCount = this.prescriptions.filter(med => med.source === 'manual').length;
        
        if (existingMedCount > 0) {
            let syncMessage = `🔄 Syncing with Epic FHIR...\n\n`;
            
            if (manualMedCount > 0) {
                syncMessage += `Your ${manualMedCount} manually added medications will be preserved.\n`;
                syncMessage += `Demo/FHIR medications will be updated with latest data from Epic.`;
            } else {
                syncMessage += `All medications will be updated with latest data from Epic FHIR.`;
            }
            
            console.log(syncMessage);
        }

        try {
            this.showNotification('🔄 Syncing with Epic FHIR...', 'info');
            
            await this.loadFHIRData();
            this.renderCalendar();
            this.renderPrescriptionList();
            this.scheduleAllReminders();
            
            const modeText = this.fhirClient.demoMode ? ' (Demo Mode)' : '';
            this.showNotification(`✅ Synchronized with Epic FHIR${modeText}`, 'success');
            
        } catch (error) {
            console.error('❌ FHIR sync failed:', error);
            this.showNotification(`❌ Failed to sync with Epic FHIR: ${error.message}`, 'error');
        }
    }

    // ========================================================================
    // MOCK FHIR DATA - Realistic prescription data structure
    // ========================================================================
    
    loadMockFHIRData() {
        if (this.prescriptions.length === 0) {
            this.prescriptions = [
                {
                    id: 'med-001',
                    medicationName: 'Lisinopril',
                    dosage: '10mg',
                    frequency: 'once-daily',
                    times: ['08:00'],
                    startDate: this.formatDate(new Date()),
                    endDate: null,
                    foodInstructions: 'no-restriction',
                    specialInstructions: 'For blood pressure control',
                    reminderTime: CONFIG.APP.DEFAULT_REMINDER_TIME,
                    color: 'blue',
                    active: true,
                    source: 'demo', // Track source for replacement logic
                    importedAt: new Date().toISOString(),
                    fhirData: {
                        resourceType: 'MedicationRequest',
                        id: 'med-001',
                        status: 'active',
                        intent: 'order',
                        medicationCodeableConcept: {
                            coding: [{
                                system: 'http://www.nlm.nih.gov/research/umls/rxnorm',
                                code: '29046',
                                display: 'Lisinopril'
                            }]
                        },
                        dosageInstruction: [{
                            timing: {
                                repeat: {
                                    frequency: 1,
                                    period: 1,
                                    periodUnit: 'd'
                                }
                            },
                            doseQuantity: {
                                value: 10,
                                unit: 'mg'
                            }
                        }]
                    }
                },
                {
                    id: 'med-002',
                    medicationName: 'Metformin',
                    dosage: '500mg',
                    frequency: 'twice-daily',
                    times: ['08:00', '20:00'],
                    startDate: this.formatDate(new Date()),
                    endDate: null,
                    foodInstructions: 'with-food',
                    specialInstructions: 'Take with meals to reduce stomach upset',
                    reminderTime: CONFIG.APP.DEFAULT_REMINDER_TIME,
                    color: 'green',
                    active: true,
                    source: 'demo', // Track source for replacement logic
                    importedAt: new Date().toISOString(),
                    fhirData: {
                        resourceType: 'MedicationRequest',
                        id: 'med-002',
                        status: 'active',
                        intent: 'order',
                        medicationCodeableConcept: {
                            coding: [{
                                system: 'http://www.nlm.nih.gov/research/umls/rxnorm',
                                code: '6809',
                                display: 'Metformin'
                            }]
                        }
                    }
                },
                {
                    id: 'med-003',
                    medicationName: 'Omeprazole',
                    dosage: '20mg',
                    frequency: 'once-daily',
                    times: ['07:30'],
                    startDate: this.formatDate(new Date()),
                    endDate: this.formatDate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)),
                    foodInstructions: 'before-meals',
                    specialInstructions: 'Take 30 minutes before breakfast',
                    reminderTime: CONFIG.APP.DEFAULT_REMINDER_TIME,
                    color: 'purple',
                    active: true,
                    source: 'demo', // Track source for replacement logic
                    importedAt: new Date().toISOString(),
                    fhirData: {
                        resourceType: 'MedicationRequest',
                        id: 'med-003',
                        status: 'active',
                        intent: 'order'
                    }
                }
            ];
            this.saveData();
            console.log('📋 Loaded demo medications for testing');
        }
    }

    // ========================================================================
    // EVENT LISTENERS
    // ========================================================================
    
    setupEventListeners() {
        // Sidebar functionality
        document.getElementById('sidebarToggle').addEventListener('click', () => this.toggleSidebar());
        document.getElementById('menuToggle').addEventListener('click', () => this.toggleSidebar());
        
        // Tab navigation - improved to handle nested elements
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                // Find the tab element even if clicking on child elements
                let targetTab = e.target;
                while (targetTab && !targetTab.classList.contains('nav-tab')) {
                    targetTab = targetTab.parentElement;
                }
                
                if (targetTab && targetTab.dataset.tab) {
                    this.switchTab(targetTab.dataset.tab);
                }
            });
        });

        // Calendar navigation
        document.getElementById('prevBtn').addEventListener('click', () => this.navigateCalendar(-1));
        document.getElementById('nextBtn').addEventListener('click', () => this.navigateCalendar(1));
        document.getElementById('todayBtn').addEventListener('click', () => this.goToToday());

        // View selector
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.changeView(e.target.dataset.view));
        });

        // Modals
        document.getElementById('addPrescriptionBtn').addEventListener('click', () => this.openPrescriptionModal());
        document.getElementById('closeModal').addEventListener('click', () => this.closePrescriptionModal());
        document.getElementById('closeDoseModal').addEventListener('click', () => this.closeDoseModal());

        // Forms
        document.getElementById('prescriptionForm').addEventListener('submit', (e) => this.savePrescription(e));
        document.getElementById('frequency').addEventListener('change', (e) => this.updateTimeInputs(e.target.value));

        // Modal actions
        document.getElementById('cancelBtn').addEventListener('click', () => this.closePrescriptionModal());

        // Reminder actions
        document.getElementById('sendAllRemindersBtn').addEventListener('click', () => this.sendAllReminders());

        // Settings
        document.getElementById('saveSettingsBtn').addEventListener('click', () => this.saveSettingsFromSidebar());

        // Epic FHIR integration
        const syncEpicBtn = document.getElementById('syncEpicFHIRBtn');
        if (syncEpicBtn) {
            syncEpicBtn.addEventListener('click', () => this.syncWithEpicFHIR());
        }

        // Dose modal actions
        document.getElementById('markTakenBtn').addEventListener('click', () => this.markDose('taken'));
        document.getElementById('markSkippedBtn').addEventListener('click', () => this.markDose('skipped'));
        document.getElementById('sendReminderBtn').addEventListener('click', () => this.sendIndividualReminder());

        // Quick actions
        document.getElementById('quickAddBtn').addEventListener('click', () => this.openPrescriptionModal());

        // Close modals on outside click
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                e.target.classList.remove('active');
            }
        });

        // Handle window resize
        window.addEventListener('resize', () => this.handleResize());
    }

    // ========================================================================
    // CALENDAR RENDERING
    // ========================================================================
    
    renderCalendar() {
        const container = document.getElementById('calendarContainer');
        const currentDateElement = document.getElementById('currentDate');
        
        // Update current date display
        currentDateElement.textContent = this.getDateRangeText();
        
        // Clear container
        container.innerHTML = '';
        
        // Render based on current view
        switch (this.currentView) {
            case 'day':
                this.renderDayView(container);
                break;
            case 'three-day':
                this.renderThreeDayView(container);
                break;
            case 'week':
                this.renderWeekView(container);
                break;
            case 'month':
                this.renderMonthView(container);
                break;
        }
    }

    renderDayView(container) {
        const dayDiv = document.createElement('div');
        dayDiv.className = 'day-view';
        
        const grid = document.createElement('div');
        grid.className = 'calendar-grid';
        grid.style.display = 'grid';
        grid.style.gridTemplateColumns = '100px 1fr';
        grid.style.gridTemplateRows = 'auto 1fr';
        grid.style.height = '600px';
        
        // Header
        const emptyHeader = document.createElement('div');
        emptyHeader.className = 'calendar-header-cell';
        emptyHeader.style.gridColumn = '1';
        emptyHeader.style.gridRow = '1';
        
        const dayHeader = document.createElement('div');
        dayHeader.className = 'calendar-header-cell';
        dayHeader.style.gridColumn = '2';
        dayHeader.style.gridRow = '1';
        dayHeader.textContent = this.formatDayHeader(this.currentDate);
        
        grid.appendChild(emptyHeader);
        grid.appendChild(dayHeader);
        
        // Create scrollable content area
        const scrollArea = document.createElement('div');
        scrollArea.style.gridColumn = '1 / -1';
        scrollArea.style.gridRow = '2';
        scrollArea.style.overflowY = 'auto';
        scrollArea.style.display = 'grid';
        scrollArea.style.gridTemplateColumns = '100px 1fr';
        scrollArea.style.gridAutoRows = 'minmax(60px, max-content)'; // Allow rows to expand to content size
        scrollArea.style.alignItems = 'start'; // Changed from stretch to start for natural sizing
        scrollArea.style.alignContent = 'start'; // Align grid content to start
        
        // Time slots
        for (let hour = 6; hour < 24; hour++) {
            const timeLabel = document.createElement('div');
            timeLabel.className = 'time-label';
            timeLabel.textContent = this.formatTime(hour, 0);
            scrollArea.appendChild(timeLabel);
            
            const timeSlot = document.createElement('div');
            timeSlot.className = 'time-slot';
            this.addEventsToTimeSlot(timeSlot, this.currentDate, hour);
            scrollArea.appendChild(timeSlot);
        }
        
        grid.appendChild(scrollArea);
        dayDiv.appendChild(grid);
        container.appendChild(dayDiv);
    }

    renderThreeDayView(container) {
        const threeDayDiv = document.createElement('div');
        threeDayDiv.className = 'three-day-view';
        
        const grid = document.createElement('div');
        grid.className = 'calendar-grid';
        grid.style.display = 'grid';
        grid.style.gridTemplateColumns = '100px repeat(3, 1fr)';
        grid.style.gridTemplateRows = 'auto 1fr';
        grid.style.height = '600px';
        
        // Header
        const emptyHeader = document.createElement('div');
        emptyHeader.className = 'calendar-header-cell';
        emptyHeader.style.gridColumn = '1';
        emptyHeader.style.gridRow = '1';
        
        grid.appendChild(emptyHeader);
        
        for (let i = 0; i < 3; i++) {
            const date = new Date(this.currentDate);
            date.setDate(date.getDate() + i);
            
            const headerCell = document.createElement('div');
            headerCell.className = 'calendar-header-cell';
            headerCell.style.gridColumn = `${i + 2}`;
            headerCell.style.gridRow = '1';
            headerCell.textContent = this.formatDayHeader(date);
            grid.appendChild(headerCell);
        }
        
        // Create scrollable content area
        const scrollArea = document.createElement('div');
        scrollArea.style.gridColumn = '1 / -1';
        scrollArea.style.gridRow = '2';
        scrollArea.style.overflowY = 'auto';
        scrollArea.style.display = 'grid';
        scrollArea.style.gridTemplateColumns = '100px repeat(3, 1fr)';
        scrollArea.style.gridAutoRows = 'minmax(60px, max-content)'; // Allow rows to expand to content size
        scrollArea.style.alignItems = 'start'; // Changed from stretch to start for natural sizing
        scrollArea.style.alignContent = 'start'; // Align grid content to start
        
        // Time slots
        for (let hour = 6; hour < 24; hour++) {
            const timeLabel = document.createElement('div');
            timeLabel.className = 'time-label';
            timeLabel.textContent = this.formatTime(hour, 0);
            scrollArea.appendChild(timeLabel);
            
            for (let day = 0; day < 3; day++) {
                const date = new Date(this.currentDate);
                date.setDate(date.getDate() + day);
                
                const timeSlot = document.createElement('div');
                timeSlot.className = 'time-slot';
                this.addEventsToTimeSlot(timeSlot, date, hour);
                scrollArea.appendChild(timeSlot);
            }
        }
        
        grid.appendChild(scrollArea);
        threeDayDiv.appendChild(grid);
        container.appendChild(threeDayDiv);
    }

    renderWeekView(container) {
        const weekDiv = document.createElement('div');
        weekDiv.className = 'week-view';
        
        const grid = document.createElement('div');
        grid.className = 'calendar-grid';
        grid.style.display = 'grid';
        grid.style.gridTemplateColumns = '100px repeat(7, 1fr)';
        grid.style.gridTemplateRows = 'auto 1fr';
        grid.style.height = '600px';
        
        // Get week start (Sunday)
        const weekStart = this.getWeekStart(this.currentDate);
        
        // Header
        const emptyHeader = document.createElement('div');
        emptyHeader.className = 'calendar-header-cell';
        emptyHeader.style.gridColumn = '1';
        emptyHeader.style.gridRow = '1';
        
        grid.appendChild(emptyHeader);
        
        const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        for (let i = 0; i < 7; i++) {
            const date = new Date(weekStart);
            date.setDate(date.getDate() + i);
            
            const headerCell = document.createElement('div');
            headerCell.className = 'calendar-header-cell';
            headerCell.style.gridColumn = `${i + 2}`;
            headerCell.style.gridRow = '1';
            headerCell.textContent = `${dayNames[i]} ${date.getDate()}`;
            grid.appendChild(headerCell);
        }
        
        // Create scrollable content area
        const scrollArea = document.createElement('div');
        scrollArea.style.gridColumn = '1 / -1';
        scrollArea.style.gridRow = '2';
        scrollArea.style.overflowY = 'auto';
        scrollArea.style.display = 'grid';
        scrollArea.style.gridTemplateColumns = '100px repeat(7, 1fr)';
        scrollArea.style.gridAutoRows = 'minmax(60px, max-content)'; // Allow rows to expand to content size
        scrollArea.style.alignItems = 'start'; // Changed from stretch to start for natural sizing
        scrollArea.style.alignContent = 'start'; // Align grid content to start
        
        // Time slots
        for (let hour = 6; hour < 24; hour++) {
            const timeLabel = document.createElement('div');
            timeLabel.className = 'time-label';
            timeLabel.textContent = this.formatTime(hour, 0);
            scrollArea.appendChild(timeLabel);
            
            for (let day = 0; day < 7; day++) {
                const date = new Date(weekStart);
                date.setDate(date.getDate() + day);
                
                const timeSlot = document.createElement('div');
                timeSlot.className = 'time-slot';
                this.addEventsToTimeSlot(timeSlot, date, hour);
                scrollArea.appendChild(timeSlot);
            }
        }
        
        grid.appendChild(scrollArea);
        weekDiv.appendChild(grid);
        container.appendChild(weekDiv);
    }

    renderMonthView(container) {
        const monthDiv = document.createElement('div');
        monthDiv.className = 'month-view';
        
        const grid = document.createElement('div');
        grid.className = 'calendar-grid';
        grid.style.display = 'grid';
        grid.style.gridTemplateColumns = 'repeat(7, 1fr)';
        grid.style.gridTemplateRows = 'auto repeat(6, 1fr)';
        grid.style.height = '600px';
        grid.style.gap = '1px';
        grid.style.backgroundColor = '#e2e8f0';
        grid.style.padding = '1px';
        grid.style.borderRadius = '8px';
        grid.style.overflow = 'hidden';
        
        // Header
        const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        dayNames.forEach((day, index) => {
            const headerCell = document.createElement('div');
            headerCell.className = 'calendar-header-cell';
            headerCell.style.gridColumn = `${index + 1}`;
            headerCell.style.gridRow = '1';
            headerCell.style.backgroundColor = '#f8fafc';
            headerCell.style.padding = '12px 8px';
            headerCell.style.fontWeight = '600';
            headerCell.style.fontSize = '14px';
            headerCell.style.textAlign = 'center';
            headerCell.style.borderBottom = '2px solid #e2e8f0';
            headerCell.textContent = day;
            grid.appendChild(headerCell);
        });
        
        // Calendar cells
        const monthStart = new Date(this.currentDate.getFullYear(), this.currentDate.getMonth(), 1);
        const monthEnd = new Date(this.currentDate.getFullYear(), this.currentDate.getMonth() + 1, 0);
        const startDate = this.getWeekStart(monthStart);
        const endDate = new Date(startDate);
        endDate.setDate(endDate.getDate() + 41); // 6 weeks
        
        const currentDate = new Date(startDate);
        let row = 2;
        let col = 1;
        
        while (currentDate <= endDate && row <= 7) {
            const cell = document.createElement('div');
            cell.className = 'calendar-cell';
            cell.style.gridColumn = `${col}`;
            cell.style.gridRow = `${row}`;
            cell.style.backgroundColor = '#ffffff';
            cell.style.padding = '8px';
            cell.style.minHeight = '80px';
            cell.style.position = 'relative';
            cell.style.overflow = 'hidden';
            
            if (currentDate.getMonth() !== this.currentDate.getMonth()) {
                cell.style.backgroundColor = '#f8fafc';
                cell.style.opacity = '0.6';
            }
            
            if (this.isSameDay(currentDate, new Date())) {
                cell.style.backgroundColor = '#e6fffa';
                cell.style.borderLeft = '3px solid #38b2ac';
            }
            
            const dateDiv = document.createElement('div');
            dateDiv.className = 'cell-date';
            dateDiv.style.fontWeight = '600';
            dateDiv.style.marginBottom = '4px';
            dateDiv.style.fontSize = '14px';
            dateDiv.textContent = currentDate.getDate();
            cell.appendChild(dateDiv);
            
            // Add events for this day
            this.addEventsToCell(cell, new Date(currentDate));
            
            grid.appendChild(cell);
            
            col++;
            if (col > 7) {
                col = 1;
                row++;
            }
            
            currentDate.setDate(currentDate.getDate() + 1);
        }
        
        monthDiv.appendChild(grid);
        container.appendChild(monthDiv);
    }

    // ========================================================================
    // EVENT MANAGEMENT
    // ========================================================================
    
    addEventsToTimeSlot(slot, date, hour) {
        const events = this.getEventsForDateTime(date, hour);
        events.forEach(event => {
            const eventElement = this.createEventElement(event);
            slot.appendChild(eventElement);
        });
    }

    addEventsToCell(cell, date) {
        const events = this.getEventsForDate(date);
        events.forEach(event => {
            const eventElement = this.createEventElement(event, true);
            cell.appendChild(eventElement);
        });
    }

    createEventElement(event, showTime = false) {
        const eventDiv = document.createElement('div');
        eventDiv.className = `calendar-event ${event.color}`;
        
        if (event.foodInstructions === 'with-food') {
            eventDiv.classList.add('with-food');
        } else if (event.foodInstructions === 'without-food') {
            eventDiv.classList.add('without-food');
        }
        
        if (event.taken) {
            eventDiv.classList.add('taken');
        }
        
        if (event.overdue) {
            eventDiv.classList.add('overdue');
        }
        
        // Different styling for month view
        if (showTime) {
            eventDiv.style.fontSize = '10px';
            eventDiv.style.padding = '2px 4px';
            eventDiv.style.margin = '1px 0';
            eventDiv.style.borderRadius = '3px';
            eventDiv.style.lineHeight = '1.2';
            
            const timeText = ` ${event.time}`;
            eventDiv.textContent = `${event.medicationName}${timeText}`;
            eventDiv.title = `${event.medicationName} ${event.dosage} at ${event.time}`;
        } else {
            eventDiv.textContent = `${event.medicationName} ${event.dosage}`;
            eventDiv.title = `${event.medicationName} ${event.dosage} at ${event.time}`;
        }
        
        eventDiv.addEventListener('click', () => this.openDoseModal(event));
        
        return eventDiv;
    }

    getEventsForDate(date) {
        const events = [];
        const dateStr = this.formatDate(date);
        
        this.prescriptions.forEach(prescription => {
            if (!prescription.active) return;
            
            const startDate = new Date(prescription.startDate);
            const endDate = prescription.endDate ? new Date(prescription.endDate) : null;
            
            if (date < startDate || (endDate && date > endDate)) return;
            
            prescription.times.forEach(time => {
                const eventId = `${prescription.id}-${dateStr}-${time}`;
                const doseRecord = this.doseHistory.find(d => d.eventId === eventId);
                
                events.push({
                    ...prescription,
                    time,
                    date: dateStr,
                    eventId,
                    taken: doseRecord?.status === 'taken',
                    skipped: doseRecord?.status === 'skipped',
                    overdue: this.isEventOverdue(date, time)
                });
            });
        });
        
        return events.sort((a, b) => a.time.localeCompare(b.time));
    }

    getEventsForDateTime(date, hour) {
        return this.getEventsForDate(date).filter(event => {
            const eventHour = parseInt(event.time.split(':')[0]);
            return eventHour === hour;
        });
    }

    isEventOverdue(date, time) {
        const now = new Date();
        const eventDateTime = new Date(date);
        const [hours, minutes] = time.split(':').map(Number);
        eventDateTime.setHours(hours, minutes, 0, 0);
        
        return eventDateTime < now;
    }

    // ========================================================================
    // PRESCRIPTION MANAGEMENT
    // ========================================================================
    
    openPrescriptionModal(prescription = null) {
        const modal = document.getElementById('prescriptionModal');
        const form = document.getElementById('prescriptionForm');
        const title = document.getElementById('modalTitle');
        
        // Clear any previous data completely
        form.reset();
        
        // Remove any existing hidden ID field first
        const existingHiddenId = form.querySelector('input[name="id"]');
        if (existingHiddenId) {
            existingHiddenId.remove();
        }
        
        if (prescription) {
            title.textContent = 'Edit Prescription';
            console.log('Editing prescription:', prescription.id, prescription.medicationName);
            
            // Create and add hidden ID field for editing
            const hiddenId = document.createElement('input');
            hiddenId.type = 'hidden';
            hiddenId.name = 'id';
            hiddenId.value = prescription.id;
            form.appendChild(hiddenId);
            
            this.populateForm(form, prescription);
        } else {
            title.textContent = 'Add Prescription';
            console.log('Adding new prescription');
            document.getElementById('startDate').value = this.formatDate(new Date());
            this.updateTimeInputs('once-daily');
        }
        
        modal.classList.add('active');
    }

    closePrescriptionModal() {
        document.getElementById('prescriptionModal').classList.remove('active');
    }

    populateForm(form, prescription) {
        // First populate all basic fields
        Object.keys(prescription).forEach(key => {
            const input = form.querySelector(`[name="${key}"]`);
            if (input && key !== 'times') {
                input.value = prescription[key];
            }
        });
        
        // Then handle times specially - update time inputs based on frequency first
                    this.updateTimeInputs(prescription.frequency);
        
        // Wait for DOM update, then populate time values
        setTimeout(() => {
                    const timeInputs = form.querySelectorAll('.time-input');
                    prescription.times.forEach((time, index) => {
                        if (timeInputs[index]) {
                            timeInputs[index].value = time;
                        }
                    });
        }, 10);
    }

    updateTimeInputs(frequency) {
        const container = document.getElementById('timesContainer');
        const frequencyMap = {
            'once-daily': 1,
            'twice-daily': 2,
            'three-times-daily': 3,
            'four-times-daily': 4,
            'every-other-day': 1,
            'weekly': 1
        };
        
        const count = frequencyMap[frequency] || 1;
        // Better default times that are more realistic
        const defaultTimes = {
            'once-daily': ['08:00'],
            'twice-daily': ['08:00', '20:00'],
            'three-times-daily': ['08:00', '14:00', '20:00'],
            'four-times-daily': ['08:00', '12:00', '16:00', '20:00'],
            'every-other-day': ['08:00'],
            'weekly': ['08:00']
        };
        
        const times = defaultTimes[frequency] || ['08:00'];
        
        container.innerHTML = '';
        for (let i = 0; i < count; i++) {
            const input = document.createElement('input');
            input.type = 'time';
            input.className = 'time-input';
            input.value = times[i] || '08:00';
            input.required = true;
            container.appendChild(input);
        }
    }

    savePrescription(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);
        
        const times = Array.from(form.querySelectorAll('.time-input')).map(input => input.value);
        
        // Get ID from hidden field or generate new one
        const existingId = formData.get('id');
        const prescriptionId = existingId || `med-${Date.now()}`;
        
        console.log('Saving prescription - ID from form:', existingId, 'Final ID:', prescriptionId);
        
        const prescription = {
            id: prescriptionId,
            medicationName: formData.get('medicationName'),
            dosage: formData.get('dosage'),
            frequency: formData.get('frequency'),
            times: times,
            startDate: formData.get('startDate'),
            endDate: formData.get('endDate') || null,
            foodInstructions: formData.get('foodInstructions'),
            specialInstructions: formData.get('specialInstructions'),
            reminderTime: parseInt(formData.get('reminderTime')),
            color: formData.get('color'),
            active: true,
            source: 'manual', // Track that this was manually added
            createdAt: new Date().toISOString(),
            fhirData: {
                resourceType: 'MedicationRequest',
                id: prescriptionId,
                status: 'active',
                intent: 'order'
            }
        };
        
        // Find and replace existing prescription or add new one
        const existingIndex = this.prescriptions.findIndex(p => p.id === prescriptionId);
        console.log('Existing prescription index:', existingIndex);
        console.log('Current prescriptions before save:', this.prescriptions.map(p => ({ id: p.id, name: p.medicationName })));
        
        if (existingIndex >= 0) {
            console.log('Updating existing prescription at index:', existingIndex);
            // Preserve the original source when updating
            prescription.source = this.prescriptions[existingIndex].source || 'manual';
            prescription.createdAt = this.prescriptions[existingIndex].createdAt || prescription.createdAt;
            prescription.updatedAt = new Date().toISOString();
            this.prescriptions[existingIndex] = prescription;
        } else {
            console.log('Adding new prescription');
            this.prescriptions.push(prescription);
        }
        
        console.log('Prescriptions after save:', this.prescriptions.map(p => ({ id: p.id, name: p.medicationName, source: p.source })));
        
        // Save and refresh all displays
        this.saveData();
        this.scheduleAllReminders(); // Clear old reminders and set new ones
        this.renderCalendar();
        this.renderPrescriptionList();
        this.closePrescriptionModal();
        
        // Show success notification
        const action = existingIndex >= 0 ? 'updated' : 'added';
        this.showNotification(`Prescription ${action} successfully!`, 'success');
    }

    deletePrescription(id) {
        const prescription = this.prescriptions.find(p => p.id === id);
        const medicationName = prescription ? prescription.medicationName : 'medication';
        
        if (confirm(`Are you sure you want to delete ${medicationName}?`)) {
            this.prescriptions = this.prescriptions.filter(p => p.id !== id);
            
            // Also clean up any related dose history
            this.doseHistory = this.doseHistory.filter(d => d.prescriptionId !== id);
            
            this.saveData();
            this.scheduleAllReminders(); // Clear old reminders
            this.renderCalendar();
            this.renderPrescriptionList();
            
            this.showNotification(`${medicationName} deleted successfully!`, 'success');
        }
    }

    renderPrescriptionList() {
        const container = document.getElementById('prescriptionList');
        container.innerHTML = '';
        
        this.prescriptions.filter(p => p.active).forEach(prescription => {
            const item = document.createElement('div');
            item.className = 'prescription-item';
            
            const name = document.createElement('div');
            name.className = 'prescription-name';
            name.textContent = prescription.medicationName;
            
            const details = document.createElement('div');
            details.className = 'prescription-details';
            details.innerHTML = `
                <div>${prescription.dosage} - ${prescription.frequency.replace('-', ' ')}</div>
                <div>Times: ${prescription.times.join(', ')}</div>
                <div>Food: ${prescription.foodInstructions.replace('-', ' ')}</div>
            `;
            
            const actions = document.createElement('div');
            actions.className = 'prescription-actions';
            
            const editBtn = document.createElement('button');
            editBtn.textContent = 'Edit';
            editBtn.addEventListener('click', () => this.openPrescriptionModal(prescription));
            
            const deleteBtn = document.createElement('button');
            deleteBtn.textContent = 'Delete';
            deleteBtn.addEventListener('click', () => this.deletePrescription(prescription.id));
            
            const reminderBtn = document.createElement('button');
            reminderBtn.textContent = 'Send Reminder';
            reminderBtn.addEventListener('click', () => this.sendPrescriptionReminder(prescription));
            
            actions.appendChild(editBtn);
            actions.appendChild(deleteBtn);
            actions.appendChild(reminderBtn);
            
            item.appendChild(name);
            item.appendChild(details);
            item.appendChild(actions);
            
            container.appendChild(item);
        });
    }

    // ========================================================================
    // DOSE TRACKING
    // ========================================================================
    
    openDoseModal(event) {
        const modal = document.getElementById('doseModal');
        const title = document.getElementById('doseModalTitle');
        const info = document.getElementById('doseInfo');
        
        this.currentDoseEvent = event;
        
        title.textContent = `${event.medicationName} - ${event.time}`;
        info.innerHTML = `
            <strong>${event.medicationName} ${event.dosage}</strong><br>
            <em>Time:</em> ${event.time}<br>
            <em>Food:</em> ${event.foodInstructions.replace('-', ' ')}<br>
            ${event.specialInstructions ? `<em>Instructions:</em> ${event.specialInstructions}<br>` : ''}
            <em>Status:</em> ${event.taken ? 'Taken' : event.skipped ? 'Skipped' : 'Pending'}
        `;
        
        modal.classList.add('active');
    }

    closeDoseModal() {
        document.getElementById('doseModal').classList.remove('active');
        this.currentDoseEvent = null;
    }

    markDose(status) {
        if (!this.currentDoseEvent) return;
        
        const doseRecord = {
            eventId: this.currentDoseEvent.eventId,
            prescriptionId: this.currentDoseEvent.id,
            date: this.currentDoseEvent.date,
            time: this.currentDoseEvent.time,
            status: status,
            timestamp: new Date().toISOString()
        };
        
        const existingIndex = this.doseHistory.findIndex(d => d.eventId === this.currentDoseEvent.eventId);
        if (existingIndex >= 0) {
            this.doseHistory[existingIndex] = doseRecord;
        } else {
            this.doseHistory.push(doseRecord);
        }
        
        this.saveData();
        this.renderCalendar();
        this.closeDoseModal();
    }

    sendIndividualReminder() {
        if (!this.currentDoseEvent) return;
        
        // Send email if configured
        if (this.settings.enableEmailReminders && this.settings.email) {
            this.sendEmailReminder(this.currentDoseEvent);
        }
        
        this.closeDoseModal();
    }

    // ========================================================================
    // EMAIL REMINDERS WITH RESEND
    // ========================================================================
    
    async sendEmailReminder(event) {
        if (!this.settings.enableEmailReminders || !this.settings.email) {
            console.warn('Email reminders not configured');
            return;
        }
        
        try {
            // Check if Resend is properly configured or in demo mode
            if (!this.resendClient.isConfigured && !this.resendClient.demoMode) {
                this.showNotification('Email service not configured. Please check console for setup instructions.', 'warning');
                console.error(`
🚨 EMAIL SETUP REQUIRED:

1. Sign up at https://resend.com
2. Get your API key from the dashboard  
3. Verify your domain (or use a verified domain)
4. Update script.js lines 301-303:
   - Replace 're_123456789_REPLACE_WITH_YOUR_ACTUAL_API_KEY' with your actual API key
   - Replace 'noreply@yourdomain.com' with your verified domain email

Example:
this.apiKey = 're_your_actual_api_key_here';
this.fromEmail = 'noreply@yourverifieddomain.com';
                `);
                return;
            }

            await this.resendClient.sendReminderEmail(
                this.settings.email,
                event.medicationName,
                event.dosage,
                event.time,
                event.specialInstructions
            );
            
            if (this.resendClient.demoMode) {
                console.log('Demo email reminder sent successfully');
                this.showNotification('Demo email reminder sent! (Check console for details)', 'info');
            } else {
                console.log('Email reminder sent successfully');
                this.showNotification('Email reminder sent!', 'success');
            }
        } catch (error) {
            console.error('Error sending email reminder:', error);
            
            if (error.message.includes('not configured')) {
                this.showNotification('Email service not configured. Check console for setup instructions.', 'warning');
            } else if (error.message.includes('API key')) {
                this.showNotification('Invalid email API key. Please check your Resend configuration.', 'error');
            } else if (error.message.includes('domain')) {
                this.showNotification('Email domain not verified. Please verify your domain with Resend.', 'error');
            } else {
                this.showNotification('Failed to send email reminder. Check console for details.', 'error');
            }
        }
    }

    async sendDailySummaryEmail() {
        if (!this.settings.enableDailySummary || !this.settings.email) {
            console.warn('Daily summary email not configured');
            return;
        }

        const today = new Date();
        const todayEvents = this.getEventsForDate(today);
        
        // Group events by medication
        const medicationSummary = [];
        const processedMeds = new Set();
        
        todayEvents.forEach(event => {
            if (!processedMeds.has(event.medicationName)) {
                processedMeds.add(event.medicationName);
                const medEvents = todayEvents.filter(e => e.medicationName === event.medicationName);
                medicationSummary.push({
                    medicationName: event.medicationName,
                    dosage: event.dosage,
                    times: medEvents.map(e => e.time),
                    specialInstructions: event.specialInstructions
                });
            }
        });

        if (medicationSummary.length === 0) {
            console.log('No medications scheduled for today');
            return;
        }

        try {
            await this.resendClient.sendDailySummaryEmail(this.settings.email, medicationSummary);
            console.log('Daily summary email sent successfully');
            this.showNotification('Daily summary sent!', 'success');
        } catch (error) {
            console.error('Error sending daily summary email:', error);
            this.showNotification('Failed to send daily summary', 'error');
        }
    }

    sendAllReminders() {
        // Check if email is properly configured
        if (!this.settings.enableEmailReminders) {
            this.showNotification('Email reminders are disabled. Enable them in Settings to send reminders.', 'warning');
            return;
        }
        
        if (!this.settings.email) {
            this.showNotification('Please configure your email address in Settings before sending reminders.', 'warning');
            return;
        }
        
        const today = new Date();
        const todayEvents = this.getEventsForDate(today);
        const upcomingEvents = todayEvents.filter(event => {
            const now = new Date();
            const eventTime = new Date();
            const [hours, minutes] = event.time.split(':').map(Number);
            eventTime.setHours(hours, minutes, 0, 0);
            
            return eventTime > now && !event.taken && !event.skipped;
        });
        
        if (upcomingEvents.length === 0) {
            this.showNotification('No upcoming medication reminders for today.', 'info');
            return;
        }
        
        // Send email reminders
        let sentCount = 0;
        upcomingEvents.forEach(async (event) => {
            try {
                await this.sendEmailReminder(event);
                sentCount++;
            } catch (error) {
                console.error('Failed to send reminder for', event.medicationName, error);
            }
        });
        
        this.showNotification(`Sent ${sentCount} email reminders successfully!`, 'success');
    }

    sendPrescriptionReminder(prescription) {
        // Check if email is properly configured
        if (!this.settings.enableEmailReminders) {
            this.showNotification('Email reminders are disabled. Enable them in Settings to send reminders.', 'warning');
            return;
        }
        
        if (!this.settings.email) {
            this.showNotification('Please configure your email address in Settings before sending reminders.', 'warning');
            return;
        }
        
        const today = new Date();
        const todayEvents = this.getEventsForDate(today);
        const prescriptionEvents = todayEvents.filter(event => 
            event.id === prescription.id && !event.taken && !event.skipped
        );
        
        if (prescriptionEvents.length === 0) {
            this.showNotification(`No pending reminders for ${prescription.medicationName} today.`, 'info');
            return;
        }
        
        let sentCount = 0;
        prescriptionEvents.forEach(async (event) => {
            try {
                await this.sendEmailReminder(event);
                sentCount++;
            } catch (error) {
                console.error('Failed to send reminder for', event.medicationName, error);
            }
        });
        
        this.showNotification(`Sent ${sentCount} email reminders for ${prescription.medicationName}!`, 'success');
    }

    scheduleAllReminders() {
        // Clear existing scheduled reminders
        this.scheduledReminders.forEach(clearTimeout);
        this.scheduledReminders = [];
        
        // Don't schedule if email reminders are disabled or email not configured
        // But allow demo mode if email is configured
        if (!this.settings.enableEmailReminders || !this.settings.email) {
            this.updateReminderStatus(0);
            return;
        }
        
        // Allow scheduling in demo mode if user has configured their email
        if (!this.resendClient.isConfigured && !this.resendClient.demoMode) {
            this.updateReminderStatus(0);
            return;
        }
        
        const now = new Date();
        const endDate = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // Next 7 days
        let scheduledCount = 0;
        
        // Schedule daily summary email if enabled
        if (this.settings.enableDailySummary) {
            const [summaryHours, summaryMinutes] = this.settings.dailySummaryTime.split(':').map(Number);
            
            // Schedule for the next 7 days
            for (let day = 0; day < 7; day++) {
                const summaryTime = new Date();
                summaryTime.setDate(summaryTime.getDate() + day);
                summaryTime.setHours(summaryHours, summaryMinutes, 0, 0);
                
                if (summaryTime > now && summaryTime <= endDate) {
                    const summaryTimeout = setTimeout(() => {
                        this.sendDailySummaryEmail();
                    }, summaryTime.getTime() - now.getTime());
                    
                    this.scheduledReminders.push(summaryTimeout);
                    scheduledCount++;
                }
            }
        }
        
        // Schedule individual medication reminders
        this.prescriptions.forEach(prescription => {
            if (!prescription.active) return;
            
            prescription.times.forEach(time => {
                const [hours, minutes] = time.split(':').map(Number);
                
                // Schedule for the next 7 days
                for (let day = 0; day < 7; day++) {
                    const medicationTime = new Date();
                    medicationTime.setDate(medicationTime.getDate() + day);
                    medicationTime.setHours(hours, minutes, 0, 0);
                    
                    const reminderTime = new Date(medicationTime.getTime() - (prescription.reminderTime * 60 * 1000));
                
                if (reminderTime > now && reminderTime <= endDate) {
                    const timeout = setTimeout(() => {
                        const event = {
                            ...prescription,
                            time,
                                date: this.formatDate(medicationTime),
                                eventId: `${prescription.id}-${this.formatDate(medicationTime)}-${time}`
                        };
                        
                        const doseRecord = this.doseHistory.find(d => d.eventId === event.eventId);
                        if (!doseRecord || (doseRecord.status !== 'taken' && doseRecord.status !== 'skipped')) {
                                this.sendEmailReminder(event);
                                const modeText = this.resendClient.demoMode ? ' (Demo)' : '';
                                this.showNotification(`📧 Reminder${modeText}: Time to take ${event.medicationName} ${event.dosage}`, 'info');
                        }
                    }, reminderTime.getTime() - now.getTime());
                    
                    this.scheduledReminders.push(timeout);
                        scheduledCount++;
                    }
                }
            });
        });
        
        this.updateReminderStatus(scheduledCount);
        
        if (scheduledCount > 0) {
            const modeText = this.resendClient.demoMode ? ' (Demo Mode)' : '';
            console.log(`📅 Scheduled ${scheduledCount} automatic reminders for the next 7 days${modeText}`);
        }
    }

    updateReminderStatus(count) {
        // Update reminder status in the UI
        const statusElement = document.getElementById('reminderStatus');
        if (statusElement) {
            // Check conditions in order of priority
            if (!this.settings.enableEmailReminders) {
                statusElement.textContent = '⚠️ Email reminders disabled in settings';
                statusElement.style.color = '#f59e0b';
            } else if (!this.settings.email) {
                statusElement.textContent = '⚠️ Email address not configured';
                statusElement.style.color = '#f59e0b';
            } else if (this.resendClient.demoMode && count > 0) {
                statusElement.textContent = `🧪 ${count} demo reminders scheduled`;
                statusElement.style.color = '#8b5cf6';
            } else if (!this.resendClient.isConfigured) {
                statusElement.textContent = '⚠️ Email API not configured (see console)';
                statusElement.style.color = '#f59e0b';
            } else if (count > 0) {
                statusElement.textContent = `✅ ${count} reminders scheduled`;
                statusElement.style.color = '#22c55e';
            } else {
                statusElement.textContent = '❌ No reminders scheduled';
                statusElement.style.color = '#ef4444';
            }
        }
        
        // Update reminders tab stats
        const scheduledRemindersElement = document.getElementById('scheduledReminders');
        if (scheduledRemindersElement) {
            scheduledRemindersElement.textContent = count;
        }
    }

    // ========================================================================
    // SETTINGS MANAGEMENT
    // ========================================================================
    
    openSettingsModal() {
        const modal = document.getElementById('settingsModal');
        const form = document.getElementById('settingsForm');
        
        // Populate form with current settings
        Object.keys(this.settings).forEach(key => {
            const input = form.querySelector(`[name="${key}"]`);
            if (input) {
                if (input.type === 'checkbox') {
                    input.checked = this.settings[key];
                } else {
                    input.value = this.settings[key] || '';
                }
            }
        });
        
        modal.classList.add('active');
    }

    closeSettingsModal() {
        document.getElementById('settingsModal').classList.remove('active');
    }

    saveSettings(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);
        
        this.settings = {
            epicPatientId: formData.get('epicPatientId') || '',
            useEpicFHIR: formData.has('useEpicFHIR'),
            // Email settings
            email: formData.get('email') || '',
            enableEmailReminders: formData.has('enableEmailReminders'),
            enableDailySummary: formData.has('enableDailySummary'),
            dailySummaryTime: formData.get('dailySummaryTime') || '08:00'
        };
        
        this.saveData();
        this.scheduleAllReminders();
        this.closeSettingsModal();
        this.showNotification('Settings saved!', 'success');
    }

    // ========================================================================
    // CALENDAR NAVIGATION
    // ========================================================================
    
    changeView(view) {
        this.currentView = view;
        
        // Update active button
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === view);
        });
        
        this.renderCalendar();
    }

    navigateCalendar(direction) {
        switch (this.currentView) {
            case 'day':
                this.currentDate.setDate(this.currentDate.getDate() + direction);
                break;
            case 'three-day':
                this.currentDate.setDate(this.currentDate.getDate() + (direction * 3));
                break;
            case 'week':
                this.currentDate.setDate(this.currentDate.getDate() + (direction * 7));
                break;
            case 'month':
                this.currentDate.setMonth(this.currentDate.getMonth() + direction);
                break;
        }
        
        this.renderCalendar();
    }

    goToToday() {
        this.currentDate = new Date();
        this.renderCalendar();
    }

    // ========================================================================
    // UTILITY FUNCTIONS
    // ========================================================================
    
    formatDate(date) {
        return date.toISOString().split('T')[0];
    }

    formatTime(hours, minutes) {
        return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
    }

    formatDayHeader(date) {
        const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        return `${dayNames[date.getDay()]} ${date.getDate()}`;
    }

    getDateRangeText() {
        const options = { year: 'numeric', month: 'long', day: 'numeric' };
        
        switch (this.currentView) {
            case 'day':
                return this.currentDate.toLocaleDateString('en-US', options);
            case 'three-day':
                const endDate = new Date(this.currentDate);
                endDate.setDate(date.getDate() + 2);
                return `${this.currentDate.toLocaleDateString('en-US', options)} - ${endDate.toLocaleDateString('en-US', options)}`;
            case 'week':
                const weekStart = this.getWeekStart(this.currentDate);
                const weekEnd = new Date(weekStart);
                weekEnd.setDate(weekEnd.getDate() + 6);
                return `${weekStart.toLocaleDateString('en-US', options)} - ${weekEnd.toLocaleDateString('en-US', options)}`;
            case 'month':
                return this.currentDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
        }
    }

    getWeekStart(date) {
        const d = new Date(date);
        const day = d.getDay();
        const diff = d.getDate() - day;
        return new Date(d.setDate(diff));
    }

    isSameDay(date1, date2) {
        return date1.toDateString() === date2.toDateString();
    }

    showNotification(message, type = 'info') {
        // Simple notification system
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === 'success' ? '#22c55e' : type === 'error' ? '#ef4444' : '#3b82f6'};
            color: white;
            padding: 12px 20px;
            border-radius: 4px;
            z-index: 10000;
            font-weight: 500;
        `;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    // ========================================================================
    // SIDEBAR FUNCTIONALITY
    // ========================================================================
    
    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        if (window.innerWidth <= 1024) {
            sidebar.classList.toggle('open');
        } else {
            sidebar.classList.toggle('collapsed');
        }
    }

    switchTab(tabName) {
        // Update active tab
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabName);
        });

        // Update active content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `${tabName}-tab`);
        });

        // Update specific tab content
        this.updateTabContent(tabName);
    }

    updateTabContent(tabName) {
        switch (tabName) {
            case 'prescriptions':
                this.renderPrescriptionList();
                break;
            case 'reminders':
                this.updateReminderStats();
                break;
            case 'history':
                this.renderHistoryList();
                break;
            case 'settings':
                this.populateSettings();
                break;
        }
    }

    updateReminderStats() {
        const today = new Date();
        const todayEvents = this.getEventsForDate(today);
        const completedCount = this.doseHistory.filter(d => 
            d.date === this.formatDate(today) && d.status === 'taken'
        ).length;
        const pendingCount = todayEvents.filter(e => !e.taken && !e.skipped).length;

        document.getElementById('todayDoses').textContent = todayEvents.length;
        document.getElementById('completedDoses').textContent = completedCount;
        document.getElementById('pendingDoses').textContent = pendingCount;
    }

    renderHistoryList() {
        const container = document.getElementById('historyList');
        container.innerHTML = '';

        const recentHistory = this.doseHistory
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 20);

        if (recentHistory.length === 0) {
            container.innerHTML = '<p style="text-align: center; color: #718096; padding: 20px;">No history available</p>';
            return;
        }

        recentHistory.forEach(record => {
            const prescription = this.prescriptions.find(p => p.id === record.prescriptionId);
            if (!prescription) return;

            const item = document.createElement('div');
            item.className = 'history-item';
            
            const date = new Date(record.timestamp);
            const statusIcon = record.status === 'taken' ? '✅' : '❌';
            
            item.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>${prescription.medicationName}</strong> ${prescription.dosage}
                        <div style="font-size: 11px; color: #718096;">
                            ${record.date} at ${record.time}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div>${statusIcon} ${record.status}</div>
                        <div style="font-size: 11px; color: #718096;">
                            ${date.toLocaleTimeString()}
                        </div>
                    </div>
                </div>
            `;
            
            container.appendChild(item);
        });
    }

    populateSettings() {
        // Populate settings form with current values
        document.getElementById('epicPatientId').value = this.settings.epicPatientId || '';
        document.getElementById('useEpicFHIR').checked = this.settings.useEpicFHIR || false;
        
        // Email settings
        document.getElementById('email').value = this.settings.email || '';
        document.getElementById('enableEmailReminders').checked = this.settings.enableEmailReminders;
        document.getElementById('enableDailySummary').checked = this.settings.enableDailySummary;
        document.getElementById('dailySummaryTime').value = this.settings.dailySummaryTime || '08:00';
    }

    saveSettingsFromSidebar() {
        try {
            const newSettings = {
                epicPatientId: document.getElementById('epicPatientId')?.value?.trim() || '',
                useEpicFHIR: document.getElementById('useEpicFHIR')?.checked || false,
                // Email settings
                email: document.getElementById('email')?.value?.trim() || '',
                enableEmailReminders: document.getElementById('enableEmailReminders')?.checked || false,
                enableDailySummary: document.getElementById('enableDailySummary')?.checked || false,
                dailySummaryTime: document.getElementById('dailySummaryTime')?.value || '08:00'
            };

            // Validate Patient ID if provided
            if (newSettings.epicPatientId) {
                try {
                    this.fhirClient.validatePatientId(newSettings.epicPatientId);
                    console.log('✅ Patient ID validation passed');
                } catch (error) {
                    this.showNotification(`❌ Invalid Patient ID: ${error.message}`, 'error');
                    return; // Don't save if validation fails
                }
            }

            // Validate email if provided
            if (newSettings.email) {
                const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailPattern.test(newSettings.email)) {
                    this.showNotification('❌ Please enter a valid email address', 'error');
                    return;
                }
            }

            // Check if Epic FHIR is enabled but Patient ID is missing
            if (newSettings.useEpicFHIR && !newSettings.epicPatientId) {
                this.showNotification('❌ Patient ID is required when Epic FHIR integration is enabled', 'error');
                return;
            }

            // Check if email reminders are enabled but email is missing
            if (newSettings.enableEmailReminders && !newSettings.email) {
                this.showNotification('❌ Email address is required when email reminders are enabled', 'error');
                return;
            }

            // Save validated settings
            this.settings = newSettings;
        this.saveData();
        this.scheduleAllReminders();
        
            // If Epic FHIR settings changed and are valid, try to connect
            if (newSettings.useEpicFHIR && newSettings.epicPatientId) {
                this.showNotification('⚙️ Settings saved! Attempting to connect to Epic FHIR...', 'info');
                setTimeout(() => {
            this.connectToEpicFHIR();
                }, 1000);
            } else {
                this.showNotification('✅ Settings saved successfully!', 'success');
        }
        
        } catch (error) {
            console.error('❌ Error saving settings:', error);
            this.showNotification('❌ Failed to save settings. Please try again.', 'error');
        }
    }

    handleResize() {
        const sidebar = document.getElementById('sidebar');
        if (window.innerWidth > 1024) {
            sidebar.classList.remove('open');
        }
        this.renderCalendar();
    }

    // Initialize view selector to match current view
    initializeViewSelector() {
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === this.currentView);
        });
    }

    // Add a method to clean up duplicate prescriptions
    cleanupDuplicatePrescriptions() {
        const seen = new Set();
        const cleaned = [];
        
        this.prescriptions.forEach(prescription => {
            const key = `${prescription.medicationName}-${prescription.dosage}`;
            if (!seen.has(key)) {
                seen.add(key);
                cleaned.push(prescription);
            } else {
                console.log('Removing duplicate prescription:', prescription.medicationName);
            }
        });
        
        if (cleaned.length !== this.prescriptions.length) {
            this.prescriptions = cleaned;
            this.saveData();
            this.renderCalendar();
            this.renderPrescriptionList();
            this.showNotification('Cleaned up duplicate prescriptions', 'info');
        }
    }

    // ========================================================================
    // SECURITY AND ERROR HANDLING
    // ========================================================================

    // Monitor for suspicious activity
    monitorSecurityEvents() {
        // Log security-relevant events
        const originalConsoleError = console.error;
        console.error = (...args) => {
            // Check for potential security issues in error messages
            const errorMessage = args.join(' ').toLowerCase();
            if (errorMessage.includes('script') || errorMessage.includes('injection') || errorMessage.includes('xss')) {
                this.logSecurityEvent('Potential security threat detected in error log', args);
            }
            originalConsoleError.apply(console, args);
        };

        // Monitor localStorage access
        const originalSetItem = localStorage.setItem;
        localStorage.setItem = (key, value) => {
            if (key.includes('patient') || key.includes('fhir')) {
                console.log(`🔒 Secure data stored: ${key}`);
            }
            return originalSetItem.call(localStorage, key, value);
        };
    }

    // Log security events
    logSecurityEvent(event, details = null) {
        const securityLog = {
            timestamp: new Date().toISOString(),
            event: event,
            details: details,
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        
        console.warn('🚨 Security Event:', securityLog);
        
        // Store security events (but don't expose sensitive data)
        const securityEvents = JSON.parse(localStorage.getItem('security_events') || '[]');
        securityEvents.push(securityLog);
        
        // Keep only last 10 events to prevent storage bloat
        if (securityEvents.length > 10) {
            securityEvents.splice(0, securityEvents.length - 10);
        }
        
        localStorage.setItem('security_events', JSON.stringify(securityEvents));
    }

    // Validate all user inputs for security
    validateUserInput(input, type = 'general') {
        if (!input || typeof input !== 'string') {
            return { valid: false, error: 'Input must be a non-empty string' };
        }

        const cleanInput = input.trim();
        
        // Check for suspicious patterns
        const suspiciousPatterns = [
            /<script/i, /javascript:/i, /on\w+=/i, // XSS
            /union\s+select/i, /drop\s+table/i, // SQL injection
            /\.\.\//g, /\.\.\\/, // Path traversal
            /%[0-9a-f]{2}/i, // URL encoding
            /eval\s*\(/i, /function\s*\(/i // Code injection
        ];

        for (const pattern of suspiciousPatterns) {
            if (pattern.test(cleanInput)) {
                this.logSecurityEvent(`Suspicious pattern detected in ${type} input`, { pattern: pattern.toString(), input: cleanInput.substring(0, 50) });
                return { valid: false, error: 'Input contains potentially harmful content' };
            }
        }

        // Type-specific validation
        switch (type) {
            case 'patientId':
                return this.fhirClient.validatePatientId(cleanInput) ? { valid: true, value: cleanInput } : { valid: false, error: 'Invalid Patient ID format' };
            
            case 'email':
                const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                return emailPattern.test(cleanInput) ? { valid: true, value: cleanInput } : { valid: false, error: 'Invalid email format' };
            
            case 'medicationName':
                if (cleanInput.length > 100) return { valid: false, error: 'Medication name too long' };
                return { valid: true, value: cleanInput };
            
            case 'dosage':
                if (cleanInput.length > 50) return { valid: false, error: 'Dosage information too long' };
                return { valid: true, value: cleanInput };
            
            default:
                return { valid: true, value: cleanInput };
        }
    }

    // Enhanced error handling with user-friendly messages
    handleError(error, context = 'general', showToUser = true) {
        const errorId = `error_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        
        const errorLog = {
            id: errorId,
            timestamp: new Date().toISOString(),
            context: context,
            message: error.message || error,
            stack: error.stack,
            userAgent: navigator.userAgent
        };

        console.error(`❌ Error [${errorId}] in ${context}:`, errorLog);

        // Store error for debugging (without sensitive data)
        const errorHistory = JSON.parse(localStorage.getItem('error_history') || '[]');
        errorHistory.push({
            id: errorId,
            timestamp: errorLog.timestamp,
            context: context,
            message: error.message || error.toString()
        });

        // Keep only last 20 errors
        if (errorHistory.length > 20) {
            errorHistory.splice(0, errorHistory.length - 20);
        }
        localStorage.setItem('error_history', JSON.stringify(errorHistory));

        if (showToUser) {
            let userMessage = '';
            
            // Provide context-specific user-friendly messages
            switch (context) {
                case 'fhir_connection':
                    userMessage = '❌ Unable to connect to Epic FHIR. Please check your Patient ID and internet connection.';
                    break;
                case 'fhir_import':
                    userMessage = '❌ Failed to import medications from Epic FHIR. Your existing data is safe.';
                    break;
                case 'patient_validation':
                    userMessage = '❌ Invalid Patient ID format. Please check the format and try again.';
                    break;
                case 'email_send':
                    userMessage = '❌ Failed to send email reminder. Please check your email settings.';
                    break;
                case 'data_save':
                    userMessage = '❌ Failed to save data. Please try again or refresh the page.';
                    break;
                default:
                    userMessage = '❌ An unexpected error occurred. Please try again.';
            }

            this.showNotification(`${userMessage} (Error ID: ${errorId.substr(-8)})`, 'error');
        }

        return errorId;
    }

    // Comprehensive data backup and recovery
    createDataBackup(reason = 'manual') {
        try {
            const backupData = {
                version: '1.0',
                timestamp: new Date().toISOString(),
                reason: reason,
                data: {
                    prescriptions: this.prescriptions,
                    doseHistory: this.doseHistory,
                    settings: { ...this.settings, epicPatientId: '***REDACTED***' }, // Don't backup patient ID
                }
            };

            const backupKey = `backup_${Date.now()}`;
            localStorage.setItem(backupKey, JSON.stringify(backupData));
            
            // Keep only last 5 backups
            const allKeys = Object.keys(localStorage).filter(key => key.startsWith('backup_'));
            if (allKeys.length > 5) {
                allKeys.sort();
                for (let i = 0; i < allKeys.length - 5; i++) {
                    localStorage.removeItem(allKeys[i]);
                }
            }

            console.log(`✅ Data backup created: ${backupKey}`);
            return backupKey;
            
        } catch (error) {
            console.error('❌ Failed to create backup:', error);
            return null;
        }
    }

    // Recovery from backup
    recoverFromBackup(backupKey = null) {
        try {
            let backupData;
            
            if (backupKey) {
                backupData = localStorage.getItem(backupKey);
            } else {
                // Find most recent backup
                const allKeys = Object.keys(localStorage).filter(key => key.startsWith('backup_'));
                if (allKeys.length === 0) {
                    throw new Error('No backups available');
                }
                allKeys.sort();
                backupData = localStorage.getItem(allKeys[allKeys.length - 1]);
            }

            if (!backupData) {
                throw new Error('Backup data not found');
            }

            const backup = JSON.parse(backupData);
            
            // Restore data (except patient ID for security)
            this.prescriptions = backup.data.prescriptions || [];
            this.doseHistory = backup.data.doseHistory || [];
            
            // Restore settings but keep current patient ID
            const currentPatientId = this.settings.epicPatientId;
            this.settings = { ...backup.data.settings, epicPatientId: currentPatientId };

            this.saveData();
            this.renderCalendar();
            this.renderPrescriptionList();

            console.log('✅ Data recovered from backup');
            this.showNotification('✅ Data recovered from backup', 'success');
            return true;
            
        } catch (error) {
            console.error('❌ Failed to recover from backup:', error);
            this.showNotification('❌ Failed to recover from backup', 'error');
            return false;
        }
    }

    // System health check
    performHealthCheck() {
        const healthStatus = {
            timestamp: new Date().toISOString(),
            localStorage: false,
            fhirClient: false,
            emailClient: false,
            dataIntegrity: false,
            securityStatus: 'unknown'
        };

        try {
            // Test localStorage
            const testKey = 'health_check_test';
            localStorage.setItem(testKey, 'test');
            localStorage.removeItem(testKey);
            healthStatus.localStorage = true;
        } catch (error) {
            console.warn('⚠️ localStorage not available');
        }

        try {
            // Test FHIR client
            healthStatus.fhirClient = this.fhirClient && (this.fhirClient.isConfigured || this.fhirClient.demoMode);
        } catch (error) {
            console.warn('⚠️ FHIR client not available');
        }

        try {
            // Test email client
            healthStatus.emailClient = this.resendClient && (this.resendClient.isConfigured || this.resendClient.demoMode);
        } catch (error) {
            console.warn('⚠️ Email client not available');
        }

        try {
            // Test data integrity
            healthStatus.dataIntegrity = Array.isArray(this.prescriptions) && Array.isArray(this.doseHistory) && typeof this.settings === 'object';
        } catch (error) {
            console.warn('⚠️ Data integrity check failed');
        }

        // Security status
        const securityEvents = JSON.parse(localStorage.getItem('security_events') || '[]');
        healthStatus.securityStatus = securityEvents.length === 0 ? 'clean' : 'events_detected';

        console.log('🏥 System Health Check:', healthStatus);
        return healthStatus;
    }

    // Validate date format
    isValidDate(dateString) {
        if (!dateString) return false;
        const date = new Date(dateString);
        return date instanceof Date && !isNaN(date) && dateString.match(/^\d{4}-\d{2}-\d{2}$/);
    }
}

// ============================================================================
// DEBUG AND TESTING FUNCTIONS
// ============================================================================

// Test email configuration
window.testEmailSetup = function() {
    console.log('📧 Testing Email Configuration...');
    
    if (typeof CONFIG === 'undefined') {
        console.error('❌ CONFIG not loaded');
        return;
    }
    
    const resendConfig = CONFIG.RESEND;
    
    console.log('📊 Email Configuration Status:');
    console.log(`API Key: ${resendConfig.API_KEY.startsWith('re_') ? '✅ Valid format' : '❌ Invalid format'}`);
    console.log(`From Email: ${resendConfig.FROM_EMAIL.includes('@') ? '✅ Valid format' : '❌ Invalid format'}`);
    console.log(`Demo Mode: ${resendConfig.API_KEY.includes('YOUR_RESEND') ? '✅ Demo mode' : '❌ Production mode'}`);
    
    // Test email client
    try {
        const client = new ResendClient();
        console.log(`Email Client Status: ${client.isConfigured ? '✅ Configured' : '⚠️ Demo mode'}`);
    } catch (error) {
        console.error('❌ Email client initialization failed:', error.message);
    }
};

// Test FHIR configuration
window.testFHIRSetup = function() {
    console.log('🏥 Testing Epic FHIR Configuration...');
    
    if (typeof CONFIG === 'undefined') {
        console.error('❌ CONFIG not loaded');
        return;
    }
    
    const fhirConfig = CONFIG.EPIC_FHIR;
    
    console.log('📊 FHIR Configuration Status:');
    console.log(`Client ID: ${fhirConfig.CLIENT_ID_PRODUCTION.includes('YOUR_EPIC') ? '❌ Not configured' : '✅ Configured'}`);
    console.log(`Environment: ${fhirConfig.USE_PRODUCTION ? '🏭 Production' : '🧪 Sandbox'}`);
    console.log(`Base URL: ${fhirConfig.BASE_URL}`);
    
    // Test FHIR client
    try {
        const client = new EpicFHIRClient();
        console.log(`FHIR Client Status: ${client.isConfigured ? '✅ Configured' : '⚠️ Demo mode'}`);
    } catch (error) {
        console.error('❌ FHIR client initialization failed:', error.message);
    }
};

// Test overall system configuration
window.testSystemSetup = function() {
    console.log('🔧 Testing System Configuration...');
    
    console.log('\n=== Configuration File ===');
    if (typeof CONFIG === 'undefined') {
        console.error('❌ CONFIG not loaded - check config.js file');
        console.log('💡 Make sure to copy config.example.js to config.js');
        return;
    } else {
        console.log('✅ CONFIG loaded successfully');
    }
    
    console.log('\n=== Email Setup ===');
    testEmailSetup();
    
    console.log('\n=== FHIR Setup ===');
    testFHIRSetup();
    
    console.log('\n=== Browser Compatibility ===');
    console.log(`LocalStorage: ${typeof localStorage !== 'undefined' ? '✅ Available' : '❌ Not available'}`);
    console.log(`Fetch API: ${typeof fetch !== 'undefined' ? '✅ Available' : '❌ Not available'}`);
    console.log(`Crypto API: ${typeof crypto !== 'undefined' ? '✅ Available' : '❌ Not available'}`);
    
    console.log('\n=== Application Status ===');
    if (typeof window.prescriptionApp !== 'undefined') {
        const app = window.prescriptionApp;
        console.log(`Prescriptions: ${app.prescriptions.length} loaded`);
        console.log(`Dose History: ${app.doseHistory.length} entries`);
        console.log(`Scheduled Reminders: ${app.scheduledReminders.length} active`);
    } else {
        console.log('⚠️ Application not fully initialized');
    }
};

// ============================================================================
// INITIALIZE APPLICATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    window.prescriptionApp = new PrescriptionReminderApp();
});