// Minimal AgeLock Browser with guaranteed age selection and content filtering
const { app, BrowserWindow, ipcMain, session, net, dialog } = require('electron');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const SecurityFilter = require('./security-filter');

// Initialize security filter
let securityFilter = null;

// Create security filter after app is ready
app.whenReady().then(() => {
  try {
    securityFilter = new SecurityFilter(app);
    console.log('Security filter initialized successfully');
  } catch (error) {
    console.error('Failed to initialize security filter:', error);
  }
});

// Simple AI content filter for text
class ContentFilter {
  constructor() {
    // Vocabulary for different content categories
    this.vocabulary = {
      sexual: ['sex', 'nude', 'naked', 'porn', 'xxx', 'adult content', 'erotic', 'boobs', 'penis', 'vagina', 'masturbation', 'intercourse'],
      violence: ['kill', 'murder', 'gun', 'weapon', 'blood', 'gore', 'death', 'shooting', 'stab', 'torture', 'fight', 'war'],
      hate: ['hate', 'racist', 'discrimination', 'bigot', 'slur', 'nazi', 'white power', 'supremacy'],
      harassment: ['bully', 'harass', 'stalk', 'threat', 'intimidate', 'dox', 'swat'],
      selfHarm: ['suicide', 'self-harm', 'cutting', 'depression', 'hurt myself', 'kill myself', 'die'],
      drugs: ['cocaine', 'heroin', 'marijuana', 'weed', 'drugs', 'meth', 'ecstasy', 'lsd', 'pills'],
      gambling: ['betting', 'gamble', 'casino', 'poker', 'slots', 'lottery', 'roulette', 'blackjack', 'sportsbook', 'wager', 'bet', 'jackpot', 'bingo']
    };
    
    // Known gambling and betting domains to block for children and teenagers
    this.restrictedDomains = {
      gambling: [
        'bet365.com', 'betway.com', 'williamhill.com', 'paddypower.com', 'skybet.com',
        'ladbrokes.com', 'coral.co.uk', 'unibet.com', 'betfair.com', '888.com',
        'casinocom.com', 'pokerstars.com', 'partypoker.com', 'bwin.com', 'betfred.com',
        'draftkings.com', 'fanduel.com', 'bovada.lv', 'betonline.ag', 'stake.com',
        'casumo.com', 'leovegas.com', 'mrgreen.com', 'casinodays.com', 'betmgm.com',
        'caesars.com', 'foxbet.com', 'pointsbet.com', 'pinnacle.com', 'netbet.com'
      ]
    };
    
    // Thresholds for different age ranges
    this.thresholds = {
      children: {
        sexual: 0.1,      // Very strict for children
        violence: 0.2,
        hate: 0.1,
        harassment: 0.1,
        selfHarm: 0.1,
        drugs: 0.1,
        gambling: 0.1     // Block all gambling content for children
      },
      teenagers: {
        sexual: 0.5,      // Moderate for teenagers
        violence: 0.6,
        hate: 0.3,
        harassment: 0.3,
        selfHarm: 0.3,
        drugs: 0.3,
        gambling: 0.2     // Very strict gambling filtering for teenagers
      },
      adults: {
        sexual: 0.9,      // Minimal for adults
        violence: 0.9,
        hate: 0.7,
        harassment: 0.7,
        selfHarm: 0.7,
        drugs: 0.8,
        gambling: 0.9     // Allow gambling content for adults
      }
    };
    
    console.log('Content filter initialized');
  }
  
  // Filter text content
  filterText(text, ageRange) {
    if (!text || typeof text !== 'string') {
      return { blocked: false };
    }
    
    // Whitelist for educational searches that should never be blocked
    const educationalSearches = [
      'birds', 'animals', 'planets', 'space', 'science', 'math', 'history',
      'geography', 'dinosaurs', 'ocean', 'weather', 'plants', 'flowers',
      'insects', 'solar system', 'earth', 'moon', 'sun', 'stars', 'technology',
      'computers', 'books', 'reading', 'writing', 'art', 'music', 'sports',
      'health', 'food', 'nature', 'environment', 'recycling', 'countries',
      'continents', 'maps', 'transportation', 'vehicles', 'school'
    ];
    
    // Check if this is an educational search that should be allowed
    const lowercaseText = text.toLowerCase().trim();
    if (educationalSearches.some(term => lowercaseText === term || 
                                        lowercaseText.startsWith(term + ' ') || 
                                        lowercaseText.endsWith(' ' + term) || 
                                        lowercaseText.includes(' ' + term + ' '))) {
      console.log(`Educational search detected: "${text}" - allowing this content`);
      return { blocked: false };
    }
    
    const results = {};
    
    // Check each category
    for (const [category, words] of Object.entries(this.vocabulary)) {
      // We need to match whole words, not partial words
      const matches = words.filter(word => {
        // Create a regex that matches the whole word
        const regex = new RegExp(`\\b${word}\\b`, 'i');
        return regex.test(lowercaseText);
      });
      
      // Calculate score based on matches
      const score = matches.length > 0 ? Math.min(1, matches.length / 3) : 0;
      results[category] = score;
    }
    
    // Find highest scoring category
    let highestCategory = null;
    let highestScore = 0;
    
    for (const [category, score] of Object.entries(results)) {
      if (score > highestScore) {
        highestScore = score;
        highestCategory = category;
      }
    }
    
    // Check if content should be blocked based on age range
    const thresholds = this.thresholds[ageRange || 'adults'];
    const isBlocked = highestCategory && highestScore > thresholds[highestCategory];
    
    // Generate explanation if blocked
    let explanation = null;
    if (isBlocked) {
      const matchingWords = this.vocabulary[highestCategory].filter(word => {
        const regex = new RegExp(`\\b${word}\\b`, 'i');
        return regex.test(lowercaseText);
      });
      
      explanation = {
        category: highestCategory,
        score: highestScore,
        reason: `This content contains terms related to ${highestCategory} that are not appropriate for ${ageRange}.`,
        matchingTerms: matchingWords
      };
    }
    
    return {
      blocked: isBlocked,
      category: highestCategory,
      score: highestScore,
      explanation: explanation
    };
  }
}

// Create content filter instance
const contentFilter = new ContentFilter();

// Ensure user data directory exists
const userDataPath = app.getPath('userData');
if (!fs.existsSync(userDataPath)) {
  fs.mkdirSync(userDataPath, { recursive: true });
}

// Store the selected age range, PIN, and security questions
let selectedAgeRange = null;
const AGE_STORAGE_PATH = path.join(userDataPath, 'age-storage.json');
const PIN_STORAGE_PATH = path.join(userDataPath, 'pin-storage.json');
const SECURITY_STORAGE_PATH = path.join(userDataPath, 'security-storage.json');

// Default PIN for initial setup
const DEFAULT_PIN = '1234';

// Function to get stored PIN or create default if not exists
async function getStoredPin() {
  try {
    if (fs.existsSync(PIN_STORAGE_PATH)) {
      const pinData = JSON.parse(fs.readFileSync(PIN_STORAGE_PATH, 'utf8'));
      
      // Verify the PIN data integrity using hash
      const expectedHash = crypto.createHash('sha256').update(pinData.pin + 'agelock-pin-salt').digest('hex');
      
      if (pinData.hash === expectedHash) {
        return pinData.pin;
      } else {
        console.warn('PIN storage tampered with - hash mismatch');
        return DEFAULT_PIN;
      }
    } else {
      // Create default PIN if not exists
      await storePin(DEFAULT_PIN);
      return DEFAULT_PIN;
    }
  } catch (error) {
    console.error('Error getting stored PIN:', error);
    return DEFAULT_PIN;
  }
}

// Function to store a new PIN
async function storePin(pin) {
  try {
    // Create a hash to verify PIN integrity
    const hash = crypto.createHash('sha256').update(pin + 'agelock-pin-salt').digest('hex');
    
    // Store PIN with hash
    const pinData = {
      pin,
      hash,
      timestamp: Date.now()
    };
    
    fs.writeFileSync(PIN_STORAGE_PATH, JSON.stringify(pinData));
    return true;
  } catch (error) {
    console.error('Error storing PIN:', error);
    return false;
  }
}

// Function to get stored security questions or create default if not exists
async function getStoredSecurityQuestions() {
  try {
    if (!fs.existsSync(SECURITY_STORAGE_PATH)) {
      // Create empty security questions file if not exists
      await storeSecurityQuestions([]);
      return [];
    }
    
    // Read and parse the security data
    const fileContent = fs.readFileSync(SECURITY_STORAGE_PATH, 'utf8');
    if (!fileContent.trim()) {
      // Handle empty file
      await storeSecurityQuestions([]);
      return [];
    }
    
    const securityData = JSON.parse(fileContent);
    
    // Verify we have valid questions data
    if (!securityData.questions || !Array.isArray(securityData.questions)) {
      console.warn('Invalid security questions data format');
      return [];
    }
    
    // Verify the security data integrity using hash if hash exists
    if (securityData.hash) {
      const dataString = JSON.stringify(securityData.questions);
      const expectedHash = crypto.createHash('sha256')
        .update(dataString + 'agelock-security-salt')
        .digest('hex');
      
      if (securityData.hash !== expectedHash) {
        console.warn('Security questions storage tampered with - hash mismatch');
        return [];
      }
    }
    
    return securityData.questions || [];
  } catch (error) {
    console.error('Error getting stored security questions:', error);
    // Return empty array on error
    return [];
  }
}

// Function to store security questions
async function storeSecurityQuestions(questions) {
  try {
    // Validate input
    if (!Array.isArray(questions)) {
      console.error('Questions must be an array');
      return false;
    }
    
    // Create a hash to verify data integrity
    const dataString = JSON.stringify(questions);
    const hash = crypto.createHash('sha256')
      .update(dataString + 'agelock-security-salt')
      .digest('hex');
    
    // Prepare data to store
    const securityData = {
      questions,
      hash,
      timestamp: Date.now(),
      version: '1.0.0'  // Add version for future compatibility
    };
    
    // Write to a temporary file first
    const tempPath = SECURITY_STORAGE_PATH + '.tmp';
    fs.writeFileSync(tempPath, JSON.stringify(securityData, null, 2));
    
    // Rename temp file to actual file (atomic operation)
    if (fs.existsSync(SECURITY_STORAGE_PATH)) {
      fs.unlinkSync(SECURITY_STORAGE_PATH);
    }
    fs.renameSync(tempPath, SECURITY_STORAGE_PATH);
    
    return true;
  } catch (error) {
    console.error('Error storing security questions:', error);
    // Try to clean up temp file if it exists
    try {
      const tempPath = SECURITY_STORAGE_PATH + '.tmp';
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
    } catch (cleanupError) {
      console.error('Error cleaning up temp file:', cleanupError);
    }
    return false;
  }
}

// Global variable to store the current age range
global.ageRange = 'children'; // Default to children for safety

// Create the main window
function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    title: 'AgeLock Browser',
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'minimal-preload.js'),
      webviewTag: true,
      devTools: true,
      // Enable features needed for video playback
      webgl: true,
      plugins: true,
      // Enable hardware acceleration
      webSecurity: true,
      // Enable media features
      allowRunningInsecureContent: false,
      experimentalFeatures: true,
      // Enable autoplay for videos
      autoplayPolicy: 'user-gesture-required',
      // Enable WebRTC
      enableWebSQL: true,
      // Enable WebAudio
      webAudio: true,
      // Enable remote module for webview
      enableRemoteModule: true
    }
  });
  
  // Enable hardware acceleration
  app.commandLine.appendSwitch('enable-accelerated-mjpeg-decode');
  app.commandLine.appendSwitch('enable-accelerated-video');
  app.commandLine.appendSwitch('ignore-gpu-blacklist');
  app.commandLine.appendSwitch('enable-native-gpu-memory-buffers');
  app.commandLine.appendSwitch('enable-gpu-rasterization');
  app.commandLine.appendSwitch('enable-zero-copy');
  // Enable video codecs
  app.commandLine.appendSwitch('enable-hardware-overlays', 'single-fullscreen,single-on-top,underlay');
  // Enable media features
  app.commandLine.appendSwitch('enable-features', 'VaapiVideoDecoder,PlatformEncryptedDolbyVision');
  // Enable widevine CDM for DRM content
  app.commandLine.appendSwitch('widevine-cdm-path', path.join(app.getPath('userData'), 'WidevineCdm'));
  app.commandLine.appendSwitch('widevine-cdm-version', 'latest');

  // Load the HTML file
  mainWindow.loadFile('minimal-browser.html');
  
  // Set up security filtering after the security filter is initialized
  const setupSecurity = () => {
    if (securityFilter) {
      // Set up security filtering
      setupSecurityFiltering();
      
      // Inject popup blocker
      securityFilter.injectPopupBlocker(mainWindow.webContents);
      
      // Handle new window events to block popups
      mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        console.log(`[AgeLock] Blocked popup window to: ${url}`);
        return { action: 'deny' };
      });
      
      return true;
    }
    return false;
  };
  
  // Try to set up security immediately
  if (!setupSecurity()) {
    // If security filter isn't ready yet, wait for it
    const waitForSecurityFilter = setInterval(() => {
      if (setupSecurity()) {
        clearInterval(waitForSecurityFilter);
      }
    }, 100);
  }

  // Handle webview popup windows
  mainWindow.webContents.on('did-attach-webview', (event, webContents) => {
    // Block new windows from webview
    webContents.setWindowOpenHandler(({ url }) => {
      console.log(`[AgeLock] Blocked webview popup to: ${url}`);
      return { action: 'deny' };
    });
    
    // Inject popup blocker into webview
    webContents.on('did-finish-load', () => {
      if (securityFilter) {
        securityFilter.injectPopupBlocker(webContents);
      }
    });
  });

  // Open the DevTools in development mode
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }

  // IPC handlers for age verification and content filtering
  ipcMain.handle('set-age', async (event, ageRange) => {
    try {
      console.log(`Setting age range: ${ageRange}`);
      
      // Validate age range - make sure it's a string and properly formatted
      if (typeof ageRange !== 'string') {
        console.error(`Invalid age range type: ${typeof ageRange}`);
        return { success: false, error: 'Invalid age range type' };
      }
      
      // Normalize the age range value
      const normalizedAgeRange = ageRange.trim().toLowerCase();
      
      // Check if it's one of the valid options
      if (!['children', 'teenagers', 'adults'].includes(normalizedAgeRange)) {
        console.error(`Invalid age range value: ${normalizedAgeRange}`);
        return { success: false, error: 'Invalid age range value' };
      }
      
      // Store the age range globally and in memory
      global.ageRange = normalizedAgeRange;
      selectedAgeRange = normalizedAgeRange;
      console.log(`Age range set to: ${normalizedAgeRange}`);
      
      // Store age range in file
      const data = {
        ageRange: normalizedAgeRange,
        timestamp: Date.now(),
        hash: crypto.createHash('sha256').update(normalizedAgeRange + 'agelock-salt').digest('hex')
      };
      
      fs.writeFileSync(AGE_STORAGE_PATH, JSON.stringify(data));
      
      console.log(`Successfully set age range to: ${normalizedAgeRange}`);
      return { success: true };
    } catch (error) {
      console.error('Error setting age:', error);
      return { success: false, error: error.message };
    }
  });
  
  ipcMain.handle('get-age', async () => {
    try {
      // First check memory
      if (selectedAgeRange) {
        return { success: true, ageRange: selectedAgeRange };
      }
      
      // Then check storage
      if (fs.existsSync(AGE_STORAGE_PATH)) {
        const data = JSON.parse(fs.readFileSync(AGE_STORAGE_PATH, 'utf8'));
        
        // Verify hash to detect tampering
        const expectedHash = crypto.createHash('sha256').update(data.ageRange + 'agelock-salt').digest('hex');
        
        if (data.hash === expectedHash) {
          selectedAgeRange = data.ageRange;
          return { success: true, ageRange: data.ageRange };
        } else {
          console.warn('Age storage tampered with - hash mismatch');
          return { success: false, error: 'Age verification failed' };
        }
      }
      
      return { success: true, ageRange: null };
    } catch (error) {
      console.error('Error getting age:', error);
      return { success: false, error: error.message };
    }
  });
  
  ipcMain.handle('reset-age', async () => {
    try {
      selectedAgeRange = null;
      
      if (fs.existsSync(AGE_STORAGE_PATH)) {
        fs.unlinkSync(AGE_STORAGE_PATH);
      }
      
      return { success: true };
    } catch (error) {
      console.error('Error resetting age:', error);
      return { success: false, error: error.message };
    }
  });
  
  // PIN management IPC handlers
  ipcMain.handle('get-pin', async () => {
    try {
      const pin = await getStoredPin();
      return { success: true, isDefault: pin === DEFAULT_PIN };
    } catch (error) {
      console.error('Error in get-pin handler:', error);
      return { success: false, error: error.message };
    }
  });
  
  ipcMain.handle('set-pin', async (event, { pin, currentPin }) => {
    try {
      // Verify current PIN first
      const storedPin = await getStoredPin();
      
      if (currentPin !== storedPin && !(storedPin === DEFAULT_PIN && currentPin === '')) {
        return { success: false, error: 'Current PIN is incorrect' };
      }
      
      // Validate new PIN
      if (!pin || pin.length < 4) {
        return { success: false, error: 'PIN must be at least 4 digits' };
      }
      
      // Store new PIN
      const result = await storePin(pin);
      
      if (result) {
        return { success: true };
      } else {
        return { success: false, error: 'Failed to store PIN' };
      }
    } catch (error) {
      console.error('Error in set-pin handler:', error);
      return { success: false, error: error.message };
    }
  });
  
  ipcMain.handle('verify-pin', async (event, { pin, ageRange }) => {
    try {
      const storedPin = await getStoredPin();
      
      if (pin === storedPin) {
        return { success: true, ageRange };
      } else {
        return { success: false, error: 'Incorrect PIN' };
      }
    } catch (error) {
      console.error('Error in verify-pin handler:', error);
      return { success: false, error: error.message };
    }
  });
  
  // Security question management IPC handlers
  ipcMain.handle('get-security-questions', async () => {
    try {
      const questions = await getStoredSecurityQuestions();
      return { 
        success: true, 
        questions,
        hasCustomQuestions: questions.length > 0
      };
    } catch (error) {
      console.error('Error in get-security-questions handler:', error);
      return { success: false, error: error.message };
    }
  });
  
  ipcMain.handle('set-security-question', async (event, { question, answer }) => {
    try {
      // Validate input
      if (!question || !answer) {
        return { success: false, error: 'Question and answer are required' };
      }
      
      // Get existing questions
      const questions = await getStoredSecurityQuestions();
      
      // Add new question or update existing
      const existingIndex = questions.findIndex(q => q.question === question);
      
      if (existingIndex >= 0) {
        // Update existing question
        questions[existingIndex].answer = answer;
      } else {
        // Add new question
        questions.push({ question, answer });
      }
      
      // Store updated questions
      const result = await storeSecurityQuestions(questions);
      
      if (result) {
        return { success: true };
      } else {
        return { success: false, error: 'Failed to store security question' };
      }
    } catch (error) {
      console.error('Error in set-security-question handler:', error);
      return { success: false, error: error.message };
    }
  });
  
  ipcMain.handle('verify-security-question', async (event, { question, answer }) => {
    try {
      // Get stored questions
      const questions = await getStoredSecurityQuestions();
      
      // Find the question
      const questionData = questions.find(q => q.question === question);
      
      if (!questionData) {
        return { success: false, error: 'Question not found' };
      }
      
      // Verify answer
      if (answer === questionData.answer) {
        return { success: true };
      } else {
        return { success: false, error: 'Incorrect answer' };
      }
    } catch (error) {
      console.error('Error in verify-security-question handler:', error);
      return { success: false, error: error.message };
    }
  });
  
  ipcMain.handle('store-security-questions', async (event, questions) => {
    try {
      // Validate input
      if (!Array.isArray(questions)) {
        return { success: false, error: 'Questions must be an array' };
      }
      
      // Store questions
      const result = await storeSecurityQuestions(questions);
      
      if (result) {
        return { success: true };
      } else {
        return { success: false, error: 'Failed to store security questions' };
      }
    } catch (error) {
      console.error('Error in store-security-questions handler:', error);
      return { success: false, error: error.message };
    }
  });
  
  // Content filtering IPC handlers
  ipcMain.handle('filter-content', async (event, { text, url }) => {
    try {
      // Get current age range
      if (!selectedAgeRange) {
        const ageResult = await ipcMain.handlers['get-age']();
        if (ageResult.success && ageResult.ageRange) {
          selectedAgeRange = ageResult.ageRange;
        } else {
          return { blocked: true, error: 'Age verification required' };
        }
      }
      
      // Filter text content
      if (text) {
        const result = contentFilter.filterText(text, selectedAgeRange);
        console.log(`Content filtering result for "${text}": ${JSON.stringify(result)}`);
        return result;
      }
      
      // Filter URL (enhanced implementation with gambling site blocking)
      if (url) {
        // Extract domain and path for basic filtering
        let domain = '';
        try {
          const urlObj = new URL(url);
          domain = urlObj.hostname;
          
          // Check for known safe domains for children
          const safeDomains = [
            'kids.nationalgeographic.com',
            'pbskids.org',
            'scratch.mit.edu',
            'khanacademy.org',
            'code.org',
            'nasa.gov',
            'starfall.com',
            'abcya.com',
            'coolmath.com',
            'funbrain.com',
            'seussville.com',
            'highlightskids.com',
            'storylineonline.net',
            'brainpop.com',
            'wonderopolis.org'
          ];
          
          // Block gambling sites for children and teenagers
          if ((selectedAgeRange === 'children' || selectedAgeRange === 'teenagers') && 
              contentFilter.restrictedDomains.gambling.some(gamblingDomain => domain.includes(gamblingDomain))) {
            return {
              blocked: true,
              explanation: {
                category: 'gambling',
                reason: `This website contains gambling or betting content that is not appropriate for ${selectedAgeRange}.`,
                safeAlternatives: selectedAgeRange === 'children' ? safeDomains.slice(0, 5) : []
              }
            };
          }
          
          // For children, only allow explicitly safe domains
          if (selectedAgeRange === 'children' && !safeDomains.some(d => domain.includes(d))) {
            return {
              blocked: true,
              explanation: {
                category: 'restricted',
                reason: `This website is not on the approved list for children.`,
                safeAlternatives: safeDomains.slice(0, 5)
              }
            };
          }
          
          // Filter the URL path and query as text
          const pathAndQuery = urlObj.pathname + urlObj.search;
          if (pathAndQuery) {
            const result = contentFilter.filterText(pathAndQuery, selectedAgeRange);
            if (result.blocked) {
              return result;
            }
          }
          
          // Check domain against common patterns for gambling sites
          const gamblingPatterns = ['bet', 'casino', 'poker', 'gambling', 'slots', 'lottery', 'wager'];
          if ((selectedAgeRange === 'children' || selectedAgeRange === 'teenagers') && 
              gamblingPatterns.some(pattern => domain.includes(pattern))) {
            return {
              blocked: true,
              explanation: {
                category: 'gambling',
                reason: `This website may contain gambling or betting content that is not appropriate for ${selectedAgeRange}.`,
                safeAlternatives: selectedAgeRange === 'children' ? safeDomains.slice(0, 5) : []
              }
            };
          }
        } catch (e) {
          console.error('Error parsing URL:', e);
        }
        
        // If we reach here, the URL passed all filters
        return { blocked: false };
      }
      
      return { blocked: false };
    } catch (error) {
      console.error('Error filtering content:', error);
      return { blocked: true, error: error.message };
    }
  });
}

// Import blocking patterns
const blockingPatterns = require('./blocking-patterns');

// Set up security filtering for all requests
function setupSecurityFiltering() {
  if (!securityFilter) {
    console.error('Security filter not initialized');
    return;
  }
  
  console.log('Setting up security filtering...');
  const ses = session.defaultSession;
  
  // Compile patterns once
  const domainPatterns = blockingPatterns.hostnamePatterns.map(p => new RegExp(p));
  const pathPatterns = blockingPatterns.suspiciousPathPatterns;
  const trackingParams = blockingPatterns.trackingParams;
  
  // Set up content security policy and security headers
  ses.webRequest.onHeadersReceived((details, callback) => {
    try {
      // Add security headers
      const responseHeaders = {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: https: blob:;",
          "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: blob:;",
          "style-src 'self' 'unsafe-inline' https: blob:;",
          "img-src * data: blob: https: http:;",  // Allow images from any source
          "media-src * data: blob: https: http:;",  // Allow media from any source
          "connect-src 'self' https: wss: http:;",
          "frame-src 'self' https: blob: http:;",
          "child-src 'self' blob: https: http:;"
        ].join(' '),
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
      };
      
      callback({ cancel: false, responseHeaders });
    } catch (error) {
      console.error('Error in headers received handler:', error);
      callback({ cancel: false, responseHeaders: details.responseHeaders || {} });
    }
  });
  
  // Enhanced ad blocking rules
  const adBlockRules = {
    // Common ad networks
    adNetworks: [
      'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
      'adnxs.com', 'adroll.com', 'adsrvr.org', 'adtechus.com', 'amazon-adsystem.com',
      'casalemedia.com', 'criteo.com', 'demdex.net', 'facebook.com/tr/', 'google-analytics.com',
      'googletagmanager.com', 'googletagservices.com', 'mathtag.com', 'moatads.com',
      'outbrain.com', 'quantserve.com', 'rfihub.com', 'rubiconproject.com',
      'scorecardresearch.com', 'serving-sys.com', 'taboola.com', 'yieldmo.com', 'zedo.com',
      'a-ads.com', 'adsterra.com', 'propellerads.com', 'pubmine.com', 'revcontent.com',
      'mgid.com', 'adskeeper.co.uk', 'coinzilla.io', 'ezoic.net', 'media.net', 'mediavine.com',
      'monetag.com', 'pubmatic.com', 'smaato.net', 'smartadserver.com', 's-onetag.com',
      'yieldlab.net', 'yieldlove.com', 'adform.net', 'adspirit.de', 'ad-maven.com'
    ],
    
    // Tracking parameters to remove
    trackingParams: [
      'utm_', 'fbclid=', 'gclid=', 'gclsrc=', 'dclid=', 'msclkid=', 'mc_eid=', 'mc_cid=',
      'icid=', 'igshid=', 'yclid=', '_ga=', 'campaignid=', 'adgroupid=', 'adid='
    ],
    
    // Suspicious patterns in URLs
    suspiciousPatterns: [
      /\/ads?\//i, /\/advert/i, /\/banner/i, /\/promo/i, /\/track/i, /\/affiliate/i,
      /adserver/i, /advertise/i, /advertising/i, /advertisement/i, /adtech/i, /adcontent/i,
      /adprovider/i, /ad[-_]?unit/i, /ad[-_]?container/i, /ad[-_]?wrapper/i, /ad[-_]?slot/i,
      /ad[-_]?frame/i, /ad[-_]?block/i, /ad[-_]?space/i, /sponsor/i, /recommend/i,
      /widget/i, /teaser/i, /sticky[-_]?bar/i, /popup/i, /overlay/i, /interstitial/i,
      /floating/i, /floater/i, /notification/i, /manga[-_]?ad/i, /chapter[-_]?ad/i,
      /page[-_]?ad/i, /reader[-_]?ad/i, /content[-_]?ad/i, /in[-_]?content[-_]?ad/i,
      /native[-_]?ad/i, /video[-_]?ad/i, /preroll/i, /midroll/i, /postroll/i, /commercial/i,
      /promotion/i, /recommendation/i, /suggestion/i, /related[-_]?content/i
    ],
    
    // Known malicious domains (including coffeemanga)
    maliciousDomains: [
      'coffeemanga.com', 'mangadex.org', 'mangakakalot.com', 'mangapanda.com',
      'mangareader.net', 'mangafox.me', 'mangago.me', 'mangahere.cc', 'mangapark.net'
    ]
  };
  
  // Enhanced function to check if a URL should be blocked
  function shouldBlockUrl(url) {
    if (!url) return false;
    
    try {
      // Skip data URLs and blob URLs
      if (url.startsWith('data:') || url.startsWith('blob:')) return false;
      
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const pathname = urlObj.pathname.toLowerCase();
      const search = urlObj.search.toLowerCase();
      
      // Block known malicious domains
      if (blockingPatterns.maliciousDomains.some(domain => hostname.includes(domain))) {
        console.log(`[BLOCK] Blocked malicious domain: ${url}`);
        return true;
      }
      
      // Block known ad networks and popup domains
      const allBlockedDomains = [
        ...blockingPatterns.adNetworks,
        ...blockingPatterns.popupDomains
      ];
      
      if (allBlockedDomains.some(domain => hostname.endsWith(domain))) {
        console.log(`[BLOCK] Blocked ad/popup domain: ${url}`);
        return true;
      }
      
      // Check against blocked hostname patterns
      for (const pattern of domainPatterns) {
        if (pattern.test(hostname) || pattern.test(url)) {
          console.log(`[BLOCK] Matched blocked hostname pattern: ${url}`);
          return true;
        }
      }
      
      // Check for suspicious patterns in path or query
      for (const pattern of pathPatterns) {
        if (pattern.test(pathname) || pattern.test(search) || pattern.test(url)) {
          console.log(`[BLOCK] Suspicious path pattern: ${url}`);
          return true;
        }
      }
      
      // Check for tracking parameters
      if (trackingParams.some(param => search.includes(param))) {
        console.log(`[BLOCK] Tracking parameter detected: ${url}`);
        return true;
      }
      
      return false;
    } catch (e) {
      console.error('Error checking URL:', e);
      return false;
    }
  }
  
  // Handle all web requests with targeted ad blocking
  ses.webRequest.onBeforeRequest((details, callback) => {
    try {
      const { url, resourceType } = details;
      
      // Get current age range (default to children for safety)
      const ageRange = global.ageRange || 'children';
      
      // Handle YouTube restrictions first
      if (ageRange === 'children' || ageRange === 'teenagers') {
        const youtubeCheck = checkYoutubeRestrictions(url, ageRange);
        if (youtubeCheck.blocked) {
          console.log(`[BLOCK] YouTube restriction: ${youtubeCheck.reason} - ${url}`);
          if (youtubeCheck.redirect) {
            return callback({ redirectURL: youtubeCheck.redirect });
          }
          return callback({ cancel: true });
        }
      }
      
      // Always allow main document and media content
      if (resourceType === 'mainFrame' || resourceType === 'media' || 
          resourceType === 'stylesheet' || resourceType === 'font' ||
          resourceType === 'image' || resourceType === 'script') {
        console.log(`[ALLOW] Allowing ${resourceType}: ${url}`);
        return callback({ cancel: false });
      }
      
      // Only block known ad scripts and trackers
      if (isMaliciousAd(url)) {
        console.log(`[BLOCK] Blocking ad script: ${url}`);
        return callback({ cancel: true });
      }
      
      // Allow all other requests
      console.log(`[ALLOW] Allowing ${resourceType}: ${url}`);
      callback({ cancel: false });
      
    } catch (error) {
      console.error('Error in request handler:', error);
      callback({ cancel: false }); // Allow by default if there's an error
    }
  });
  
  // Function to specifically identify ads (not regular content)
  function isMaliciousAd(url) {
    if (!url) return false;
    
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const pathname = urlObj.pathname.toLowerCase();
      
      // Common ad server paths and patterns
      const adPatterns = [
        // Common ad server paths
        '/ads/', '/ad/', '/adserver/', '/advert/', '/banner/', '/promo/',
        // Common ad file patterns
        /\/ad\.(js|css|html?|gif|jpg|jpeg|png|svg|webp|mp4|mp3|ogg|webm)$/i,
        // Common ad network domains (only block their ad-serving paths)
        {domain: 'doubleclick.net', path: /\/(pcs\/|pagead\/)/i},
        {domain: 'googlesyndication.com', path: /\/pagead\//i},
        {domain: 'adservice.google.com', path: /\/ads?\//i},
        // Known malicious ad networks
        'adxbid.info', 'popads.net', 'popcash.net', 'propellerads.com', 'pushcrew.com',
        'pushwoosh.com', 'pushdy.com', 'pushnami.com', 'adnxs.com', 'rubiconproject.com',
        'pubmatic.com', 'openx.net', 'adform.net', 'advertising.com', 'adroll.com',
        'adblade.com', 'adcolony.com', 'criteo.com', 'indexww.com'
      ];
      
      // Check for ad patterns
      for (const pattern of adPatterns) {
        if (typeof pattern === 'string') {
          // Simple string match in path
          if (pathname.includes(pattern)) {
            console.log(`[BLOCK] Blocking ad path: ${url}`);
            return true;
          }
        } else if (pattern.domain && pattern.path) {
          // Domain + path pattern
          if (hostname.endsWith(pattern.domain) && pattern.path.test(pathname)) {
            console.log(`[BLOCK] Blocking ad network: ${url}`);
            return true;
          }
        } else if (pattern instanceof RegExp) {
          // Regular expression match
          if (pattern.test(pathname) || pattern.test(hostname)) {
            console.log(`[BLOCK] Blocking ad pattern: ${url}`);
            return true;
          }
        } else if (hostname === pattern) {
          // Exact domain match
          console.log(`[BLOCK] Blocking ad domain: ${url}`);
          return true;
        }
      }
      
      // Additional checks for specific ad-related query parameters
      const searchParams = new URLSearchParams(urlObj.search);
      const adParams = ['ad', 'ads', 'advert', 'banner', 'promo', 'sponsor', 'tracking', 'track', 'click'];
      
      for (const param of searchParams.keys()) {
        if (adParams.some(adParam => param.toLowerCase().includes(adParam))) {
          console.log(`[BLOCK] Blocking ad parameter in URL: ${url}`);
          return true;
        }
      }
      
      // Check for common ad domains in subdomains
      const subdomains = hostname.split('.');
      if (subdomains.length > 2) {
        const subdomain = subdomains[0];
        if (['ad', 'ads', 'advert', 'banner', 'promo', 'track', 'pixel'].includes(subdomain)) {
          console.log(`[BLOCK] Blocking ad subdomain: ${url}`);
          return true;
        }
      }
      
      // Allow by default if no ad patterns matched
      return false;
      
    } catch (e) {
      console.error('Error checking for ads:', e);
      return false; // Allow by default if there's an error
    }
  }
  
  // Function to check YouTube restrictions based on age range
  function checkYoutubeRestrictions(url, ageRange) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      
      // List of YouTube domains to block
      const youtubeDomains = [
        'youtube.com',
        'www.youtube.com',
        'm.youtube.com',
        'youtu.be',
        'youtube-nocookie.com',
        'youtubei.googleapis.com',
        'yt3.ggpht.com',
        'i.ytimg.com',
        'www.youtube-nocookie.com',
        'music.youtube.com',
        'gaming.youtube.com'
      ];
      
      // List of allowed YouTube Kids domains
      const youtubeKidsDomains = [
        'youtubekids.com',
        'www.youtubekids.com',
        'youtubekids.app.goo.gl'
      ];
      
      // Check if URL is a YouTube domain
      const isYoutube = youtubeDomains.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
      
      // Check if URL is a YouTube Kids domain
      const isYoutubeKids = youtubeKidsDomains.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
      
      // Handle YouTube access based on age range
      if (isYoutube) {
        if (ageRange === 'children') {
          return {
            blocked: true,
            reason: 'YouTube is blocked in kids mode. Please use YouTube Kids instead.',
            redirect: 'https://www.youtubekids.com'
          };
        } else if (ageRange === 'teenagers') {
          // For teenagers, allow YouTube but with restrictions
          return { blocked: false };
        }
      }
      
      // Allow YouTube Kids
      if (isYoutubeKids) {
        return { blocked: false };
      }
      
      return { blocked: false };
    } catch (e) {
      console.error('Error checking YouTube restrictions:', e);
      return { blocked: false };
    }
  }
  
  console.log('Security filtering is now active');
}

// App lifecycle
app.whenReady().then(() => {
  // Reset age on startup for testing purposes
  try {
    if (fs.existsSync(AGE_STORAGE_PATH)) {
      fs.unlinkSync(AGE_STORAGE_PATH);
      console.log('Age storage reset for fresh start');
    }
  } catch (error) {
    console.error('Error resetting age storage:', error);
  }
  
  createWindow();
  
  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});
