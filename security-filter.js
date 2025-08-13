// Security filter for AgeLock Browser
const fs = require('fs');
const path = require('path');

class SecurityFilter {
  constructor(app) {
    if (!app) {
      throw new Error('Electron app module is required');
    }
    this.app = app;
    
    // Safety mode settings
    this.safeSearchEnabled = true;
    this.strictMode = false; // When enabled, only whitelisted sites are allowed
    this.enableContentFiltering = true;
    this.enableLanguageFiltering = true;
    
    // YouTube restrictions for kids mode
    this.youtubeRestrictions = {
      blockYoutube: true,  // Block regular YouTube
      allowYoutubeKids: true,  // Allow YouTube Kids
      youtubeKidsDomains: [
        'youtubekids.com',
        'www.youtubekids.com',
        'youtubekids.app.goo.gl'  // Deep linking URL
      ],
      youtubeDomains: [
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
      ]
    };
    
    // Enhanced popup blocking script to be injected into all pages
    this.popupBlockingScript = `
      // Save original functions
      const originalWindowOpen = window.open;
      const originalAddEventListener = EventTarget.prototype.addEventListener;
      
      // Block all window.open attempts
      window.open = function() {
        const url = arguments[0] || 'unknown';
        console.log('[AgeLock] Blocked popup:', url);
        return null;
      };
      
      // Block showModalDialog and similar methods
      window.showModalDialog = function() {
        console.log('[AgeLock] Blocked modal dialog');
        return null;
      };
      
      // Block window.open property access
      Object.defineProperty(window, 'open', {
        get: function() {
          return function() {
            console.log('[AgeLock] Blocked window.open() call');
            return null;
          };
        },
        set: function() {}
      });
      
      // Intercept addEventListener calls for click events
      EventTarget.prototype.addEventListener = function(type, listener, options) {
        // Block click handlers that might open popups
        if (type === 'click' && listener && typeof listener.toString === 'function' && 
            /window\.open|showModalDialog|createPopup|open\(['"]_blank['"]|location\.replace/.test(listener.toString())) {
          console.log('[AgeLock] Blocked suspicious click handler');
          return function() {};
        }
        return originalAddEventListener.call(this, type, listener, options);
      };
      
      // Block all new window attempts from links
      document.addEventListener('click', function(e) {
        let target = e.target;
        while (target && target.nodeName !== 'A' && target.nodeName !== 'AREA' && target.nodeName !== 'FORM') {
          target = target.parentNode;
          if (target === document.documentElement) return;
        }
        
        if (target) {
          // Block target="_blank" without noopener
          if (target.target === '_blank' && (!target.rel || !target.rel.includes('noopener'))) {
            e.preventDefault();
            e.stopPropagation();
            console.log('[AgeLock] Blocked _blank link:', target.href);
            return false;
          }
          
          // Block javascript: links that might open popups
          if (target.href && target.href.toLowerCase().startsWith('javascript:')) {
            if (/window\.open|showModalDialog|createPopup|open\(['"]_blank['"]|location\.replace/.test(target.href)) {
              e.preventDefault();
              e.stopPropagation();
              console.log('[AgeLock] Blocked javascript: link');
              return false;
            }
          }
        }
      }, true);
      
      // Block form submissions that might open popups
      document.addEventListener('submit', function(e) {
        if (e.target && e.target.target === '_blank') {
          e.preventDefault();
          e.stopPropagation();
          console.log('[AgeLock] Blocked form submission to new window');
          return false;
        }
      }, true);
      
      // Block meta refresh redirects that might open popups
      const metaTags = document.getElementsByTagName('meta');
      for (let i = 0; i < metaTags.length; i++) {
        if (metaTags[i].httpEquiv.toLowerCase() === 'refresh') {
          metaTags[i].parentNode.removeChild(metaTags[i]);
          console.log('[AgeLock] Removed meta refresh tag');
        }
      }
    `;

    // Whitelist of approved websites (when in strict mode)
    this.whitelist = [
      '*.wikipedia.org',
      '*.khanacademy.org',
      '*.pbskids.org',
      '*.nationalgeographic.com',
      '*.duolingo.com',
      '*.code.org',
      '*.ted.com',
      '*.kiddle.co',
      '*.kids.nationalgeographic.com',
      '*.bbc.co.uk/cbeebies',
      '*.abcmouse.com',
      '*.funbrain.com',
      '*.coolmath.com',
      '*.starfall.com',
      '*.sesamestreet.org',
      '*.abcya.com',
      '*.brainpop.com',
      '*.tinkercad.com',
      '*.scratch.mit.edu',
      '*.tynker.com',
      '*.codecombat.com',
      '*.mysterydoug.com',
      '*.mysteryscience.com',
      '*.nasa.gov/kidsclub',
      '*.si.edu/kids',
      '*.timeforkids.com',
      '*.turtlediary.com'
    ];
    
    // Categories for content filtering
    this.blockedCategories = {
      'adult': true,
      'porn': true,
      'violence': true,
      'gore': true,
      'weapons': true,
      'drugs': true,
      'alcohol': true,
      'tobacco': true,
      'gambling': true,
      'hate': true,
      'racism': true,
      'terrorism': true,
      'illegal': true,
      'piracy': true,
      'nudity': true,
      'adult_sex_ed': false, // Can be toggled by parents
      'dating': false,       // Can be toggled by parents
      'social_media': false  // Can be toggled by parents
    };
    
    // Video file extensions to whitelist
    this.videoExtensions = [
      '.mp4', '.webm', '.ogg', '.mov', '.m3u8', '.mpd', '.m4v', '.avi', '.wmv', '.flv',
      '.mkv', '.3gp', '.ts', '.m2ts', '.mpg', '.mpeg', '.m4s', '.f4v', '.webm', '.ogv'
    ];
    
    // Video domains to whitelist
    this.videoDomains = [
      'youtube.com', 'youtu.be', 'youtube-nocookie.com',
      'vimeo.com', 'player.vimeo.com',
      'dailymotion.com', 'dmcdn.net',
      'twitch.tv', 'twitchcdn.net',
      'googlevideo.com', 'ytimg.com',
      'netflix.com', 'nflxvideo.net',
      'hulu.com', 'huluim.com',
      'disneyplus.com', 'disney-plus.net',
      'hbomax.com', 'hbomaxcdn.com',
      'amazonvideo.com', 'media-amazon.com'
    ];
    
    // Common ad and tracking domains
    this.adBlockList = [
      // Standard ad networks
      'doubleclick.net',
      'googleadservices.com',
      'googlesyndication.com',
      '*.adbrite.com',
      '*.adnxs.com',
      '*.adroll.com',
      '*.adsafeprotected.com',
      '*.adsrvr.org',
      '*.adtechus.com',
      '*.amazon-adsystem.com',
      '*.applovin.com',
      '*.casalemedia.com',
      '*.criteo.com',
      '*.demdex.net',
      '*.facebook.com/tr/',
      '*.google-analytics.com',
      '*.googletagmanager.com',
      '*.googletagservices.com',
      '*.mathtag.com',
      '*.moatads.com',
      '*.outbrain.com',
      '*.quantserve.com',
      '*.rfihub.com',
      '*.rubiconproject.com',
      '*.scorecardresearch.com',
      '*.serving-sys.com',
      '*.taboola.com',
      '*.yieldmo.com',
      '*.zedo.com',
      
      // Common manga/content site ad domains
      '*.a-ads.com',
      '*.adsterra.com',
      '*.propellerads.com',
      '*.pubmine.com',
      '*.revcontent.com',
      '*.taboola.com',
      '*.outbrain.com',
      '*.mgid.com',
      '*.mgid.com',
      '*.adskeeper.co.uk',
      '*.coinzilla.io',
      '*.adskeeper.com',
      '*.ad-maven.com',
      '*.adspirit.de',
      '*.adnxs.com',
      '*.ezoic.net',
      '*.media.net',
      '*.mediavine.com',
      '*.monetag.com',
      '*.pubmatic.com',
      '*.smaato.net',
      '*.smartadserver.com',
      '*.s-onetag.com',
      '*.yieldlab.net',
      '*.yieldlove.com',
      '*.yieldmo.com',
      '*.zedo.com',
      '*.adform.net',
      '*.adnxs.com',
      '*.adroll.com',
      '*.amazon-adsystem.com',
      '*.casalemedia.com',
      '*.criteo.com',
      '*.doubleclick.net',
      '*.google-analytics.com',
      '*.googletagmanager.com',
      '*.googletagservices.com',
      '*.mathtag.com',
      '*.moatads.com',
      '*.outbrain.com',
      '*.quantserve.com',
      '*.rfihub.com',
      '*.rubiconproject.com',
      '*.scorecardresearch.com',
      '*.serving-sys.com',
      '*.taboola.com',
      '*.yieldmo.com',
      '*.zedo.com'
    ];
    
    // Known malicious sites
    this.maliciousSites = [
      '*.coffeemanga.com',  // Block all subdomains of coffeemanga.com
      '*.mangadex.org',    // Common manga site with potential tracking
      '*.mangakakalot.com',
      '*.mangapanda.com',
      '*.mangareader.net',
      '*.mangafox.me',
      '*.mangago.me',
      '*.mangahere.cc',
      '*.mangapark.net',
      '*.mangakakalot.com'
    ];
    
    this.loadBlocklists();
  }

  // Load blocklists from files
  loadBlocklists() {
    try {
      // Default ad blocklist (can be extended)
      this.adBlockList = [
        // Common ad networks
        'doubleclick.net',
        'googleadservices.com',
        'googlesyndication.com',
        '*.adbrite.com',
        '*.adnxs.com',
        // Add more ad networks as needed
        
        // Common tracking domains
        '*.google-analytics.com',
        '*.facebook.net',
        '*.scorecardresearch.com',
        '*.hotjar.com',
        
        // Common malicious patterns
        '*.xyz',
        '*.top',
        '*.gq',
        '*.tk',
        '*.ml',
        '*.cf'
      ];

      // Default malicious sites list
      this.maliciousSites = [
        // Add known malicious domains here
        'phishing-site.com',
        'malware-download.com',
        'scam-website.org'
      ];

      // Load additional blocklists from user data if they exist
      this.loadUserBlocklists();
      
    } catch (error) {
      console.error('Error loading blocklists:', error);
    }
  }

  // Load user-defined blocklists
  loadUserBlocklists() {
    try {
      const userDataPath = this.app.getPath('userData');
      const adBlockPath = path.join(userDataPath, 'user-ad-blocklist.json');
      const maliciousPath = path.join(userDataPath, 'user-malicious-sites.json');

      if (fs.existsSync(adBlockPath)) {
        const userAdBlock = JSON.parse(fs.readFileSync(adBlockPath, 'utf-8'));
        this.adBlockList = [...new Set([...this.adBlockList, ...userAdBlock])];
      }

      if (fs.existsSync(maliciousPath)) {
        const userMalicious = JSON.parse(fs.readFileSync(maliciousPath, 'utf-8'));
        this.maliciousSites = [...new Set([...this.maliciousSites, ...userMalicious])];
      }
    } catch (error) {
      console.error('Error loading user blocklists:', error);
    }
  }

  // Method to inject popup blocking script
  injectPopupBlocker(webContents) {
    if (!webContents || webContents.isDestroyed()) return;
    
    try {
      // Execute the popup blocking script in all frames
      webContents.executeJavaScriptInIsolatedWorld(1, [{
        code: this.popupBlockingScript
      }]);
      
      // Also inject as a content script for new navigations
      webContents.on('did-navigate', () => {
        if (!webContents.isDestroyed()) {
          webContents.executeJavaScriptInIsolatedWorld(1, [{
            code: this.popupBlockingScript
          }]);
        }
      });
      
      console.log('[AgeLock] Popup blocker injected');
    } catch (error) {
      console.error('Error injecting popup blocker:', error);
    }
  }
  
  // Method to check if a URL is in the whitelist
  isWhitelisted(url) {
    if (!this.whitelist || this.whitelist.length === 0) return false;
    
    try {
      const { hostname } = new URL(url);
      return this.whitelist.some(pattern => {
        // Convert pattern to regex
        const regexPattern = pattern
          .replace(/\*/g, '.*')  // Convert * to .*
          .replace(/\./g, '\\.'); // Escape dots
        const regex = new RegExp(`^${regexPattern}$`, 'i');
        return regex.test(hostname);
      });
    } catch (e) {
      console.error('Error checking whitelist:', e);
      return false;
    }
  }

  // Check if URL matches any pattern in the blocklist
  isBlockedByPattern(url, patterns) {
    try {
      const { hostname } = new URL(url);
      return patterns.some(pattern => {
        if (pattern.startsWith('*.')) {
          const domain = pattern.substring(2);
          return hostname.endsWith(domain) || hostname === domain.substring(1);
        }
        return hostname === pattern;
      });
    } catch {
      return false; // Invalid URL
    }
  }

  // Heuristic checks for suspicious URLs
  isSuspiciousUrl(url) {
    try {
      const { hostname, pathname, search } = new URL(url);
      
      // IP addresses (common in malicious links)
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        return true;
      }
      
      // Hex encoded domains
      if (/^[0-9a-f]{16,}\./.test(hostname)) {
        return true;
      }
      
      // Suspicious patterns in URL
      const suspiciousPatterns = [
        /\/login\/?$/i,
        /\/account\/?$/i,
        /\/verify\/?$/i,
        /\/update\/?$/i,
        /\/wp-content\/.*\.(php|exe|dll|bat|sh)$/i,
        /\/cgi-bin\//i,
        /\/admin\//i,
        /\/wp-admin\//i,
        /\/administrator\//i
      ];
      
      return suspiciousPatterns.some(pattern => 
        pattern.test(pathname) || pattern.test(hostname) || pattern.test(search)
      );
    } catch {
      return false; // Invalid URL
    }
  }

  // Check if URL is an ad
  isAdUrl(url) {
    // Skip video content
    if (this.isVideoUrl(url)) {
      return false;
    }
    
    // Common ad path patterns
    const adPatterns = [
      /\/ads?\//i,
      /\/advert/i,
      /\/banner/i,
      /\/promo/i,
      /\/track/i,
      /\/affiliate/i,
      /adserver/i,
      /advertise/i,
      /advertising/i,
      /advertisement/i,
      /adtech/i,
      /adcontent/i,
      /adprovider/i,
      
      // Manga/Content site specific patterns
      /\/ad[-_]?unit/i,
      /\/ad[-_]?container/i,
      /\/ad[-_]?wrapper/i,
      /\/ad[-_]?slot/i,
      /\/ad[-_]?frame/i,
      /\/ad[-_]?block/i,
      /\/ad[-_]?space/i,
      /\/sponsor/i,
      /\/recommend/i,
      /\/widget/i,
      /\/teaser/i,
      /\/sticky[-_]?bar/i,
      /\/popup/i,
      /\/overlay/i,
      /\/interstitial/i,
      /\/floating/i,
      /\/floater/i,
      /\/notification/i,
      /\/manga[-_]?ad/i,
      /\/chapter[-_]?ad/i,
      /\/page[-_]?ad/i,
      /\/reader[-_]?ad/i,
      /\/content[-_]?ad/i,
      /\/in[-_]?content[-_]?ad/i,
      /\/native[-_]?ad/i,
      /\/video[-_]?ad/i,
      /\/preroll/i,
      /\/midroll/i,
      /\/postroll/i,
      /\/commercial/i,
      /\/promotion/i,
      /\/recommendation/i,
      /\/suggestion/i,
      /\/related[-_]?content/i
    ];
    
    // Common ad query parameters
    const adQueryParams = [
      'utm_',
      'ad_',
      'adid',
      'advert',
      'campaign',
      'placement',
      'promo',
      'sponsor',
      'banner',
      'track',
      'click',
      'impression',
      'viewability'
    ];
    
    // Check for ad query parameters
    try {
      const urlObj = new URL(url);
      const hasAdParam = Array.from(urlObj.searchParams.keys()).some(param => 
        adQueryParams.some(adParam => param.toLowerCase().includes(adParam))
      );
      
      if (hasAdParam) {
        return true;
      }
    } catch (e) {
      // Invalid URL, continue with other checks
    }

    try {
      const { pathname } = new URL(url);
      return adPatterns.some(pattern => pattern.test(pathname));
    } catch (e) {
      return false;
    }
  }
  
  // Check if URL is a search engine
  isSearchEngine(url) {
    if (!url) {
      console.log('[Search] No URL provided to isSearchEngine');
      return false;
    }
    
    try {
      const { hostname, pathname, search } = new URL(url);
      console.log(`[Search] Checking if URL is a search engine: ${hostname}${pathname}${search}`);
      
      // List of search engine domains and their common TLDs
      const searchEngineDomains = [
        // Google
        'google.', 'google.com', 'google.co.', 'googleusercontent.com', 'googleapis.com', 'gstatic.com',
        // Bing
        'bing.', 'bing.com', 'www.bing.com', 'msn.com', 'live.com', 'microsoft.com',
        // Yahoo
        'yahoo.', 'yahoo.com', 'search.yahoo.com', 'yahooapis.com', 'yimg.com', 'flickr.com', 'tumblr.com',
        // DuckDuckGo
        'duckduckgo.', 'duckduckgo.com', 'ddg.gg', 'duck.com', 'start.duckduckgo.com',
        // Yandex
        'yandex.', 'yandex.com', 'ya.ru', 'yandex.com.tr', 'yandex.ru', 'yandex.ua', 'yandex.kz',
        // Other popular search engines
        'baidu.com', 'sogou.com', 'soso.com', 'so.com', 'naver.com', 'daum.net',
        'nate.com', 'zum.com', 'naver.jp', 'yahoo.co.jp', 'goo.ne.jp',
        'ecosia.org', 'qwant.com', 'swisscows.com', 'mojeek.com', 'searx.me', 'gibiru.com',
        'startpage.com', 'search.brave.com', 'dogpile.com', 'metager.org', 'gigablast.com'
      ];
      
      // Check if the hostname matches any search engine domain
      const isEngine = searchEngineDomains.some(domain => {
        // For wildcard domains (ending with .)
        if (domain.endsWith('.')) {
          const match = hostname.startsWith(domain) || 
                       hostname.endsWith(domain.substring(1)) ||
                       hostname.includes(domain);
          if (match) console.log(`[Search] Matched wildcard domain: ${domain} for ${hostname}`);
          return match;
        }
        
        // For exact domains
        const match = hostname === domain || 
                     hostname.endsWith('.' + domain) ||
                     hostname.includes(domain);
        
        if (match) {
          console.log(`[Search] Matched exact domain: ${domain} for ${hostname}`);
        }
        
        return match;
      });
      
      console.log(`[Search] isSearchEngine result for ${hostname}: ${isEngine}`);
      return isEngine;
      
    } catch (e) {
      console.error('[Search] Error in isSearchEngine:', e);
      console.error('[Search] URL that caused error:', url);
      return false;
    }
  }
  
  // Check if a URL is a resource from a search engine
  isSearchEngineResource(url, referrer) {
    try {
      if (!url) {
        console.log('[Search] No URL provided to isSearchEngineResource');
        return false;
      }
      
      const { hostname, pathname } = new URL(url);
      console.log(`[Search] Checking if URL is a search engine resource: ${hostname}${pathname}`);
      
      // Common CDN and resource domains used by search engines
      const searchEngineResources = [
        // Google resources
        'gstatic.com', 'googleapis.com', 'ggpht.com', 'googleusercontent.com', 'google.com',
        // Bing resources
        'bing.net', 'bingapis.com', 'microsoft.com', 'microsoftonline.com', 'microsoft.net',
        // Yahoo resources
        'yimg.com', 'yahooapis.com', 'yahoo.com', 'yahoofs.com', 'yahoo.net',
        // DuckDuckGo resources
        'duckduckgo.com', 'ddg.gg', 'duckduckgo.net', 'duck.com', 'duckduckgo.xyz',
        // Other search engines
        'startpage.com', 'startpage.io', 'brave.com', 'bravesoftware.com', 'qwant.com',
        'ecosia.org', 'ecosia.net', 'swisscows.com', 'mojeek.com', 'searx.me', 'gibiru.com',
        'search.brave.com', 'dogpile.com', 'metager.org', 'gigablast.com', 'ask.com', 'aol.com'
      ];
      
      // Check if the domain is a search engine resource
      const isResource = searchEngineResources.some(domain => {
        const match = hostname === domain || 
                    hostname.endsWith('.' + domain) ||
                    hostname.includes(domain);
        
        if (match) {
          console.log(`[Search] Matched search engine resource domain: ${domain} for ${hostname}`);
        }
        
        return match;
      });
      
      if (isResource) {
        console.log(`[Search] Identified as search engine resource: ${hostname}`);
        return true;
      }
      
      // Check if the referrer is a search engine
      if (referrer) {
        console.log(`[Search] Checking referrer: ${referrer}`);
        const isSearchEngineRef = this.isSearchEngine(referrer);
        if (isSearchEngineRef) {
          console.log(`[Search] Allowing resource from search engine referrer: ${hostname}`);
          return true;
        }
      }
      
      console.log(`[Search] Not a search engine resource: ${hostname}`);
      return false;
      
    } catch (e) {
      console.error('[Search] Error in isSearchEngineResource:', e);
      console.error('[Search] URL that caused error:', url);
      console.error('[Search] Referrer:', referrer);
      return false;
    }
  }
  
  // Check if URL is a kid-friendly image or resource
  isKidFriendlyResource(url, resourceType) {
    if (!url) return false;
    
    try {
      const { hostname, pathname, searchParams } = new URL(url.toLowerCase());
      const fullUrl = hostname + pathname;
      const searchQuery = searchParams.toString().toLowerCase();
      
      // Expanded list of educational and kid-friendly domains
      const kidFriendlyDomains = [
        // Educational platforms
        'pbskids.org', 'sesamestreet.org', 'abcmouse.com', 'starfall.com', 
        'funbrain.com', 'abcya.com', 'turtlediary.com', 'highlightskids.com',
        'pbs.org', 'pbslearningmedia.org', 'natgeokids.com', 'khanacademy.org',
        'khanacademykids.org', 'ducksters.com', 'easyscienceforkids.com',
        'kids.nationalgeographic.com', 'britishcouncil.org', 'learnenglishkids.britishcouncil.org',
        'storynory.com', 'stories.audible.com', 'vooks.com', 'epic.com', 'readingiq.com',
        'homerlearning.com', 'funbrainjr.com', 'mystorybook.com', 'storyjumper.com',
        'storybird.com', 'storylineonline.net', 'oxfordowl.co.uk', 'raz-kids.com',
        'readingeggs.com', 'abcmouse.com', 'adventureacademy.com', 'tynker.com',
        'code.org', 'scratch.mit.edu', 'codecombat.com', 'typingclub.com',
        
        // Kids' entertainment and stories
        'disney.com', 'disneyjunior.com', 'disneynow.com', 'disneyplus.com',
        'nickjr.com', 'nickelodeon.com', 'nickelodeonjunior.com', 'nick.com',
        'cartoonnetwork.com', 'cocomelon.com', 'pinkfong.com', 'supersimple.com',
        'mothergooseclub.com', 'superwhy.com', 'leapfrog.com', 'pbskids.org/video',
        'pbskids.org/games', 'sesamestreet.org/games', 'sesamestreet.org/videos',
        
        // Educational content providers
        'scholastic.com', 'teacherspayteachers.com', 'education.com', 'teachersfirst.com',
        'readwritethink.org', 'readworks.org', 'commonlit.org', 'newsela.com',
        'brainpop.com', 'brainpopjr.com', 'mysteryscience.com', 'mysteryscience.com/kids',
        'mysteryscience.com/lessons', 'mysteryscience.com/mini-lessons',
        'mysteryscience.com/school-closure-planning', 'mysteryscience.com/school-closure-planning/kindergarten',
        'mysteryscience.com/school-closure-planning/1st-grade', 'mysteryscience.com/school-closure-planning/2nd-grade',
        'mysteryscience.com/school-closure-planning/3rd-grade', 'mysteryscience.com/school-closure-planning/4th-grade',
        'mysteryscience.com/school-closure-planning/5th-grade', 'mysteryscience.com/school-closure-planning/6th-grade',
        'mysteryscience.com/school-closure-planning/7th-grade', 'mysteryscience.com/school-closure-planning/8th-grade'
      ];
      
      // Expanded list of kid-friendly paths and keywords
      const kidFriendlyPaths = [
        // Age groups
        '/kids/', '/children/', '/child/', '/toddler/', '/preschool/', '/kindergarten/',
        '/elementary/', '/primary/', '/grade-', '/grade_', '/grade/', 'grade=',
        
        // Learning categories
        '/education/', '/learning/', '/teach/', '/teacher/', '/student/',
        '/classroom/', '/homeschool/', '/homeschooling/', '/lesson/', '/lessons/',
        
        // Subject areas
        '/reading/', '/math/', '/science/', '/history/', '/social-studies/',
        '/geography/', '/art/', '/music/', '/drama/', '/pe/', 'physical-education/',
        
        // Content types
        '/stories/', '/story/', '/books/', '/book/', '/rhymes/', '/rhyme/',
        '/songs/', '/song/', '/poems/', '/poem/', '/poetry/', '/nursery-rhymes/',
        '/nursery_rhymes/', '/nurseryrhymes/', '/nurseryrhyme/', '/nursery-rhyme/',
        
        // Educational activities
        '/worksheets/', '/printables/', '/activities/', '/games/', '/game/',
        '/puzzles/', '/puzzle/', '/quizzes/', '/quiz/', '/exercises/',
        
        // Creative content
        '/colors/', '/colours/', '/shapes/', '/numbers/', '/alphabet/',
        '/abc/', '/123/', '/counting/', '/coloring/', '/colouring/',
        '/drawing/', '/painting/', '/crafts/', '/craft/', '/art-projects/',
        
        // Special categories
        '/animals/', '/nature/', '/space/', '/dinosaurs/', '/transportation/',
        '/community/', '/family/', '/friends/', '/feelings/', '/emotions/'
      ];
      
      // Keywords in URL that indicate educational or kid-friendly content
      const educationalKeywords = [
        'kids', 'children', 'child', 'toddler', 'preschool', 'kindergarten',
        'elementary', 'primary', 'grade', 'learn', 'teach', 'teacher', 'student',
        'classroom', 'homeschool', 'education', 'learning', 'school', 'nursery',
        'rhyme', 'rhymes', 'story', 'stories', 'book', 'books', 'read', 'reading',
        'color', 'colour', 'colors', 'colours', 'shape', 'shapes', 'number', 'numbers',
        'alphabet', 'abc', '123', 'counting', 'math', 'science', 'art', 'music',
        'craft', 'crafts', 'activity', 'activities', 'game', 'games', 'puzzle', 'puzzles'
      ];
      
      // Common image CDNs and content delivery networks
      const safeImageHosts = [
        'ytimg.com', 'ggpht.com', 'gstatic.com', 'googleusercontent.com',
        'yimg.com', 'yahooapis.com', 'bing.net', 'microsoft.com', 'akamaihd.net',
        'cloudfront.net', 'amazonaws.com', 'cdnjs.com', 'cloudflare.com', 'wp.com',
        'wp.com', 'blogspot.com', 'blogger.com', 'wordpress.com', 'wixsite.com',
        'weebly.com', 'squarespace.com', 'wixmp.com', 's3.amazonaws.com',
        's3.us-east-2.amazonaws.com', 's3.us-west-2.amazonaws.com', 's3.dualstack.us-east-1.amazonaws.com'
      ];
      
      // Check if it's a known kid-friendly domain
      const isKidFriendlyDomain = kidFriendlyDomains.some(domain => 
        hostname.endsWith(domain) || hostname.includes(domain)
      );
      
      // Check if it's a known safe image host
      const isSafeImageHost = safeImageHosts.some(host => 
        hostname.endsWith(host) || hostname.includes(host)
      );
      
      // Check for kid-friendly paths
      const hasKidFriendlyPath = kidFriendlyPaths.some(path => 
        fullUrl.includes(path)
      );
      
      // Check for educational keywords in URL
      const hasEducationalKeyword = educationalKeywords.some(keyword => 
        fullUrl.includes(keyword) || searchQuery.includes(keyword)
      );
      
      // Common image file extensions
      const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp', '.ico'];
      const isImage = resourceType === 'image' || 
                    imageExtensions.some(ext => url.toLowerCase().endsWith(ext));
      
      // If it's an image and from a kid-friendly or safe source, allow it
      if (isImage && (isKidFriendlyDomain || isSafeImageHost || hasKidFriendlyPath || hasEducationalKeyword)) {
        console.log(`[KidSafe] Allowing kid-friendly image: ${url}`);
        return true;
      }
      
      // For non-image resources, check various conditions
      return isKidFriendlyDomain || hasKidFriendlyPath || hasEducationalKeyword;
      
    } catch (e) {
      console.error('[KidSafe] Error checking kid-friendly resource:', e);
      return false;
    }
  }
  
  // Main method to check if a request should be blocked
  shouldBlockRequest(details) {
    const { url, resourceType, referrer } = details;
    
    // Always allow images, styles, fonts, and media
    const safeResourceTypes = ['image', 'stylesheet', 'font', 'media', 'script', 'xhr', 'fetch'];
    if (safeResourceTypes.includes(resourceType)) {
      console.log(`[ALLOW] Safe resource type: ${resourceType} - ${url}`);
      return false;
    }
    
    // Skip data URLs and browser internal URLs
    if (url.startsWith('data:') || url.startsWith('chrome-extension:') || url.startsWith('chrome:')) {
      console.log(`[ALLOW] Internal URL: ${url}`);
      return false;
    }
    
    // Skip common web resources
    const allowedDomains = [
      'google.com', 'gstatic.com', 'googleapis.com', 'doubleclick.net',
      'youtube.com', 'ytimg.com', 'ggpht.com', 'yimg.com', 'yahooapis.com',
      'bing.com', 'bing.net', 'microsoft.com', 'live.com', 'office.net',
      'facebook.com', 'fbcdn.net', 'twitter.com', 'twimg.com', 't.co',
      'cloudflare.com', 'cloudfront.net', 'amazonaws.com', 'akamaihd.net',
      'wikipedia.org', 'wikimedia.org', 'mozilla.org', 'mozilla.net',
      'apple.com', 'apple-cloudkit.com', 'cdn-apple.com', 'icloud.com'
    ];
    
    try {
      const { hostname } = new URL(url);
      const isAllowedDomain = allowedDomains.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
      
      if (isAllowedDomain) {
        console.log(`[ALLOW] Allowed domain: ${hostname}`);
        return false;
      }
    } catch (e) {
      console.error('Error parsing URL:', e);
    }
    
    // First, check for gambling sites - these should always be blocked
    if (this.isGamblingSite(url)) {
      console.log(`[Security] Blocked gambling site: ${url}`);
      return {
        cancel: true,
        reason: 'Gambling content is not allowed',
        category: 'Gambling',
        url: url
      };
    }
    
    // Check if this is a search engine request
    const isSearchEngine = this.isSearchEngine(url);
    const isSearchEngineRes = this.isSearchEngineResource(url, referrer);
    
    console.log(`[Search] isSearchEngine: ${isSearchEngine}, isSearchEngineResource: ${isSearchEngineRes} for ${url}`);
    
    // Always allow search engine requests and their resources
    if (isSearchEngine || isSearchEngineRes) {
      console.log(`[Search] Allowing search engine resource: ${url}`);
      
      // Still enforce SafeSearch for search engine pages
      if (isSearchEngine) {
        console.log(`[SafeSearch] Checking search engine: ${url}`);
        const safeUrl = this.enforceSafeSearch(url);
        if (safeUrl !== url) {
          console.log(`[SafeSearch] Enforcing for search: ${url} -> ${safeUrl}`);
          return { 
            cancel: false,
            redirectUrl: safeUrl,
            reason: 'SafeSearch redirection',
            originalUrl: url
          };
        }
      }
      
      console.log(`[Search] Allowing search-related resource: ${url}`);
      return {
        cancel: false,
        reason: 'Search engine resource',
        isSearchEngine,
        isSearchEngineResource: isSearchEngineRes
      };
    }
    
    // Enforce SafeSearch for other search engines
    const safeUrl = this.enforceSafeSearch(url);
    if (safeUrl !== url) {
      console.log(`[SafeSearch] Enforced for: ${url}`);
      return { redirectUrl: safeUrl };
    }
    
    // Skip whitelist check for search results and their resources
    const isSearchResult = referrer && this.isSearchEngine(referrer);
    if (this.strictMode && !isSearchResult && !this.isWhitelisted(url)) {
      console.log(`[Security] Blocked - Not in whitelist: ${url}`);
      return true;
    }
    
    // Always allow video content that's already been verified
    if (this.isVideoUrl(url)) {
      return false;
    }
    
    // Check for explicit content in URL
    if (this.isExplicitUrl(url)) {
      console.log(`[Content Filter] Blocked explicit content: ${url}`);
      return true;
    }
    
    // Check against known malicious sites
    if (this.isBlockedByPattern(url, this.maliciousSites)) {
      console.log(`[Security] Blocked malicious site: ${url}`);
      return true;
    }
    
    // Check against ad blocklist
    if (this.isBlockedByPattern(url, this.adBlockList)) {
      console.log(`[AdBlock] Blocked ad/tracker: ${url}`);
      return true;
    }
    
    // Block common tracking and analytics
    if (this.isTrackingUrl(url)) {
      console.log(`[Tracker] Blocked tracking URL: ${url}`);
      return true;
    }
    
    // Heuristic checks for suspicious URLs
    if (this.isSuspiciousUrl(url)) {
      console.log(`[Security] Blocked suspicious URL: ${url}`);
      return true;
    }
    
    // Check for ad patterns in URL
    if (this.isAdUrl(url)) {
      console.log(`[AdBlock] Blocked ad URL pattern: ${url}`);
      return true;
    }
    
    // Block third-party trackers
    if (this.isThirdPartyTracker(details)) {
      console.log(`[Tracker] Blocked third-party tracker: ${url}`);
      return true;
    }
    
    // Block known content farm and low-quality domains
    if (this.isContentFarm(url)) {
      console.log(`[Security] Blocked content farm: ${url}`);
      return true;
    }
    
    // Additional checks for main frame requests
    if (resourceType === 'mainFrame' || resourceType === 'subFrame') {
      // Block known social media if disabled
      if (!this.blockedCategories['social_media'] && this.isSocialMedia(url)) {
        console.log(`[Content Filter] Blocked social media: ${url}`);
        return true;
      }
      
      // Block known gaming sites if needed
      if (this.blockedCategories['gaming'] && this.isGamingSite(url)) {
        console.log(`[Content Filter] Blocked gaming site: ${url}`);
        return true;
      }
    }
    
    return false;
  }
  
  // Check if a URL points to a video file or streaming source
  isVideoUrl(url) {
    if (!url) return false;
    
    // Skip data URLs and browser internal URLs
    if (url.startsWith('data:') || url.startsWith('chrome-extension:') || url.startsWith('chrome:')) {
      return false;
    }
    
    try {
      const lowerUrl = url.toLowerCase();
      const parsedUrl = new URL(lowerUrl);
      const pathname = parsedUrl.pathname.toLowerCase();
      
      // Check if URL has a video file extension
      const hasVideoExtension = this.videoExtensions.some(ext => pathname.endsWith(ext));
      if (hasVideoExtension) return true;
      
      // Check common video path patterns
      const videoPathPatterns = [
        /\/videoplayback\?/,  // YouTube video URLs
        /\/manifest\//,       // DASH manifests
        /\/hls\//,           // HLS streams
        /\/dash\//,          // DASH streams
        /\/videos?\//,       // Common video paths
        /\/video\d+\//,      // Numbered video paths
        /\.m3u8/,            // HLS playlist
        /\.mpd$/,            // DASH manifest
        /\.ism\//,           // Smooth Streaming
        /\/hls_manifest\.m3u8/,
        /\/manifest\.mpd/,
        /\/index\.m3u8/,
        /\/master\.m3u8/,
        /\/playlist\.m3u8/
      ];
      
      const hasVideoPath = videoPathPatterns.some(pattern => 
        pathname.match(pattern) || lowerUrl.match(pattern)
      );
      
      if (hasVideoPath) return true;
      
      // Check if URL is from a known video domain
      const isVideoDomain = this.videoDomains.some(domain => {
        // Handle wildcard subdomains
        if (domain.startsWith('*.')) {
          const rootDomain = domain.substring(2);
          return parsedUrl.hostname.endsWith(rootDomain);
        }
        return parsedUrl.hostname === domain || 
               parsedUrl.hostname.endsWith('.' + domain);
      });
      
      if (isVideoDomain) return true;
      
      // Check for video query parameters
      const videoParams = [
        'mime=video',
        'format=mp4',
        'type=mp4',
        'stream_type=video',
        'content_type=video',
        'video=true',
        'is_video=true',
        'media_type=video'
      ];
      
      const searchParams = new URLSearchParams(parsedUrl.search);
      const hasVideoParam = Array.from(searchParams.entries()).some(([key, value]) => {
        const param = `${key}=${value}`.toLowerCase();
        return videoParams.some(vp => param.includes(vp));
      });
      
      return hasVideoParam;
    } catch (e) {
      console.error('Error parsing URL in isVideoUrl:', e);
      return false;
    }
  }

  // Check if URL is a known tracking URL
  isTrackingUrl(url) {
    // Skip video content
    if (this.isVideoUrl(url)) {
      return false;
    }
    
    const trackingPatterns = [
      /analytics/i,
      /track/i,
      /telemetry/i,
      /metrics/i,
      /pixel/i,
      /beacon/i,
      /tag/i,
      /collect/i,
      /stat/i,
      /counter/i,
      /log/i,
      /event/i,
      /click/i,
      /impression/i,
      /conversion/i,
      /affiliate/i,
      /partner/i
    ];
    
    try {
      const { hostname, pathname } = new URL(url);
      return trackingPatterns.some(pattern => 
        pattern.test(hostname) || pattern.test(pathname)
      );
    } catch (e) {
      return false;
    }
  }
  
  // Check if the request is from a third-party tracker
  isThirdPartyTracker(details) {
    try {
      if (!details.referrer) return false;
      
      const referrerHost = new URL(details.referrer).hostname;
      const requestHost = new URL(details.url).hostname;
      
      // Skip video content
      if (this.isVideoUrl(details.url)) {
        return false;
      }
      
      // If the request is to a different domain and looks like a tracker
      if (referrerHost !== requestHost && !requestHost.endsWith(`.${referrerHost}`)) {
        return this.isTrackingUrl(details.url) || this.isAdUrl(details.url);
      }
    } catch (e) {
      // Invalid URL, continue
    }
    return false;
  }
  
  // Check if URL is a known content farm or low-quality site
  isContentFarm(url) {
    // Skip video content
    if (this.isVideoUrl(url)) {
      return false;
    }
    
    const contentFarmPatterns = [
      /coffeemanga\.com/i,
      /mangakakalot\.com/i,
      /mangapanda\.com/i,
      /mangareader\.net/i,
      /mangafox\.me/i,
      /mangago\.me/i,
      /mangahere\.cc/i,
      /mangapark\.net/i,
      /mangadex\.org/i
    ];
    
    try {
      const { hostname } = new URL(url);
      return contentFarmPatterns.some(pattern => pattern.test(hostname));
    } catch (e) {
      return false;
    }
  }
  
  // Check if URL is in the whitelist or is a search engine resource
  isWhitelisted(url) {
    // Always allow in non-strict mode
    if (!this.strictMode) return true;
    
    try {
      const { hostname, pathname } = new URL(url);
      
      // Allow search engines and their resources
      if (this.isSearchEngine(url)) {
        return true;
      }
      
      // Allow common CDNs and resources used by search engines
      const allowedResources = [
        '*.gstatic.com', '*.googleapis.com', '*.ggpht.com',
        '*.bing.net', '*.yimg.com', '*.yahooapis.com',
        '*.duckduckgo.com', '*.ddg.gg', '*.startpage.com',
        '*.brave.com', '*.bravesoftware.com', '*.startpage.gg',
        '*.mojeek.com', '*.mojeekcdn.com', '*.mojeek.link',
        '*.qwant.com', '*.qwant.net', '*.qwant.art',
        '*.ecosia.org', '*.ecosia.net', '*.ecosia.xyz',
        '*.searx.me', '*.searx.space', '*.searxng.org',
        '*.gibiru.com', '*.gibiru.xyz', '*.gibiru.net',
        '*.swisscows.com', '*.swisscows.ch', '*.swisscows.org'
      ];
      
      // Check against resource whitelist
      if (allowedResources.some(domain => {
        if (domain.startsWith('*.')) {
          const rootDomain = domain.substring(2);
          return hostname.endsWith(rootDomain);
        }
        return hostname === domain;
      })) {
        return true;
      }
      
      // Check against main whitelist
      return this.whitelist.some(domain => {
        if (domain.startsWith('*.')) {
          const rootDomain = domain.substring(2);
          return hostname.endsWith(rootDomain) || 
                 hostname === rootDomain.substring(1) ||
                 (hostname + pathname).includes(domain.replace('*.', ''));
        }
        return hostname === domain || 
               (hostname + pathname).includes(domain);
      });
    } catch (e) {
      console.error('Error in isWhitelisted:', e);
      return false;
    }
  }
  
  // Enforce SafeSearch for search engines
  enforceSafeSearch(url) {
    if (!this.safeSearchEnabled) return url;
    
    try {
      const urlObj = new URL(url);
      const { hostname, pathname, searchParams } = urlObj;
      
      // Define search engine configurations
      const searchEngines = {
        // Google
        'google.': {
          param: 'safe',
          value: 'active',
          domains: ['google.', 'googleusercontent.com'],
          additionalParams: {
            'safeui': 'on',
            'ssui': 'on'
          }
        },
        // Bing
        'bing.': {
          param: 'adlt',
          value: 'strict',
          domains: ['bing.'],
          additionalParams: {
            'adlt': 'strict',
            'adlt_required': 1
          }
        },
        // DuckDuckGo
        'duckduckgo.': {
          param: 'kp',
          value: '1',
          domains: ['duckduckgo.', 'start.duckduckgo.']
        },
        // Yahoo
        'yahoo.': {
          param: 'vm',
          value: 'r',
          domains: ['yahoo.'],
          additionalParams: {
            'fr': 'sfp',
            'iscapirx': '1',
            'vm': 'r',
            'fp': '1',
            'nojs': '1'
          }
        },
        // Yandex
        'yandex.': {
          param: 'family',
          value: 'yes',
          domains: ['yandex.']
        },
        // Other search engines
        'baidu.': { param: 'safe', value: 'on' },
        'ask.': { param: 'k', value: 'safe' },
        'ecosia.': { param: 'tts', value: 'strict' },
        'qwant.': { param: 'safesearch', value: '1' },
        'swisscows.': { param: 'safesearch', value: '1' },
        'gibiru.': { param: 'safesearch', value: '1' },
        'search.brave.': { param: 'safesearch', value: 'strict' },
        'dogpile.': { param: 'safesearch', value: 'on' },
        'metager.': { param: 'safesearch', value: '1' },
        'mojeek.': { param: 'safesearch', value: '1' },
        'gigablast.': { param: 'safesearch', value: '1' },
        'searx.': { param: 'safesearch', value: '1' }
      };
      
      // Find matching search engine configuration
      const [engineName, engineConfig] = Object.entries(searchEngines).find(([key, config]) => {
        const domains = config.domains || [key];
        return domains.some(domain => hostname.includes(domain));
      }) || [];
      
      if (engineConfig) {
        const { param, value, additionalParams = {} } = engineConfig;
        
        // Set main safe search parameter
        searchParams.set(param, value);
        
        // Set any additional parameters
        Object.entries(additionalParams).forEach(([p, v]) => {
          searchParams.set(p, v);
        });
        
        // Special handling for specific search engines
        if (engineName.includes('google.')) {
          // Remove any existing safe search parameters that might conflict
          ['safeui', 'ssui'].forEach(p => searchParams.set(p, 'on'));
          
          // Ensure safe search is on for image search
          if (pathname.startsWith('/search') && pathname.includes('tbm=isch')) {
            searchParams.set('tbs', 'itp:safe,itp:images' + (searchParams.get('tbs') || ''));
          }
        } else if (engineName.includes('bing.')) {
          // Ensure safe search is on for image search
          if (pathname.startsWith('/images/search')) {
            searchParams.set('qft', (searchParams.get('qft') || '') + '+filterui:imagesize-large');
          }
        }
        
        console.log(`[SafeSearch] Applied to ${urlObj.hostname}`);
        return urlObj.toString();
      }
    } catch (e) {
      console.error('Error enforcing SafeSearch:', e);
    }
    
    return url;
  }
  
  // Check for explicit content in text
  hasExplicitContent(text) {
    if (!this.enableContentFiltering) return false;
    
    if (!text) return false;
    
    const explicitPatterns = [
      // Profanity and explicit language
      /\b(ass(hole)?|bitch|bastard|cock|dick|fuck|shit|piss|pussy|cunt|whore|slut)/i,
      /\b(sex|nude|naked|rape|incest|pedo|molest|orgasm|masturbat|erotic|xxx|porn)/i,
      /\b(nud(e|ity)|fetish|bdsm|bondage|blowjob|handjob|dildo|vibrator|condom|viagra|cialis)/i,
      
      // Violence
      /\b(kill|murder|suicide|bomb|shoot|gun|knife|weapon|assault|abuse|torture|behead)/i,
      
      // Drugs and alcohol
      /\b(drugs?|cocaine|heroin|marijuana|molly|ecstasy|lsd|meth|opioid|oxycodone|vicodin)/i,
      /\b(alcohol|beer|whiskey|vodka|rum|tequila|wine|drunk|intoxicated|binge\s*drink)/i,
      
      // Hate speech
      /\b(nazi|kkk|white\s*power|supremacist|racist|sexist|homophob|transphob|bigot)/i,
      
      // Self-harm
      /\b(suicid(e|al)|self\s*harm|cutting|self\s*injur|anorex|bulim|eating\s*disorder)/i
    ];
    
    return explicitPatterns.some(pattern => pattern.test(text));
  }
  
  // Check if URL contains explicit content
  isExplicitUrl(url) {
    if (!this.enableContentFiltering) return false;
    
    try {
      const { hostname, pathname, search } = new URL(url.toLowerCase());
      const urlText = hostname + pathname + search;
      
      // Check for explicit content in URL
      if (this.hasExplicitContent(urlText)) {
        return true;
      }
      
      // Check for blocked categories in URL
      const blockedCategoryPatterns = {
        'adult': /\b(adult|porn|sex|xxx|nude|naked|erotic|escort|hooker|prostitut|webcam|cams?)\b/i,
        'violence': /\b(violence|gore|blood|kill|murder|gun|knife|weapon|war|terror|bomb|shoot)\b/i,
        'drugs': /\b(drugs?|cocaine|heroin|marijuana|molly|ecstasy|lsd|meth|opioid|oxycodone|vicodin)\b/i,
        'alcohol': /\b(alcohol|beer|whiskey|vodka|rum|tequila|wine|drunk|intoxicated)\b/i,
        'gambling': /\b(casino|poker|blackjack|roulette|bet|gamble|slot\s*machine|lottery|bingo)\b/i,
        'hate': /\b(nazi|kkk|hate|racis|supremacist|sexis|homophob|transphob|bigot)\b/i,
        'illegal': /\b(hack|crack|keygen|warez|torrent|pirat|illegal|counterfeit|fraud|scam|phish)\b/i
      };
      
      // Check if any blocked category is present in the URL
      for (const [category, pattern] of Object.entries(blockedCategoryPatterns)) {
        if (this.blockedCategories[category] && pattern.test(urlText)) {
          return true;
        }
      }
      
      return false;
    } catch (e) {
      return false;
    }
  }
  
  // Check if URL is a social media site
  isSocialMedia(url) {
    try {
      const { hostname } = new URL(url);
      const socialMediaDomains = [
        'facebook.com', 'fb.com', 'twitter.com', 'x.com', 'instagram.com',
        'tiktok.com', 'linkedin.com', 'pinterest.com', 'reddit.com',
        'tumblr.com', 'snapchat.com', 'whatsapp.com', 'telegram.org',
        'discord.com', 'discord.gg', 'twitch.tv', 'youtube.com', 'youtu.be',
        'vimeo.com', 'tinder.com', 'bumble.com', 'grindr.com', 'meetup.com',
        'wechat.com', 'weibo.com', 'qq.com', 'vk.com', 'ok.ru', 't.me',
        'line.me', 'kakaotalk.com', 'weverse.io', 'fandom.com', 'aminoapps.com',
        'wattpad.com', 'deviantart.com', 'flickr.com', 'vsco.co', 'behance.net',
        'dribbble.com', 'medium.com', 'tumblr.com', 'patreon.com', 'onlyfans.com',
        'substack.com', 'quora.com', 'nextdoor.com', 'goodreads.com', 'letterboxd.com',
        'last.fm', 'rateyourmusic.com', 'myanimelist.net', 'anilist.co', 'trakt.tv',
        'untappd.com', 'duolingo.com', 'memrise.com', 'babbel.com', 'busuu.com'
      ];
      
      return socialMediaDomains.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
    } catch (e) {
      return false;
    }
  }
  
  // Check if URL is a gaming site
  isGamingSite(url) {
    try {
      const { hostname } = new URL(url);
      const gamingDomains = [
        'steampowered.com', 'steamcommunity.com', 'store.steampowered.com',
        'epicgames.com', 'store.epicgames.com', 'gog.com', 'gogdb.org',
        'ubisoft.com', 'uplay.com', 'origin.com', 'ea.com', 'battle.net',
        'blizzard.com', 'playoverwatch.com', 'worldofwarcraft.com',
        'minecraft.net', 'mojang.com', 'xbox.com', 'xboxlive.com',
        'playstation.com', 'sonyentertainmentnetwork.com', 'nintendo.com',
        'nintendolife.com', 'nintendoeverything.com', 'ign.com', 'gamespot.com',
        'kotaku.com', 'polygon.com', 'pcgamer.com', 'rockpapershotgun.com',
        'eurogamer.net', 'destructoid.com', 'gameinformer.com', 'gamesradar.com',
        'gamefaqs.com', 'giantbomb.com', 'twitch.tv', 'mixer.com', 'smash.gg',
        'speedrun.com', 'speedrunslive.com', 'speedrun.community', 'speedrun.tv',
        'speedrunslive.com', 'speedrun.tv', 'speedrun.community'
      ];
      
      return gamingDomains.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
    } catch (e) {
      return false;
    }
  }
  
  // Check if URL is a gambling site
  isGamblingSite(url) {
    if (!url) {
      console.log('[Security] No URL provided to isGamblingSite');
      return false;
    }
    
    try {
      const { hostname, pathname, href } = new URL(url.toLowerCase());
      const urlStr = hostname + pathname;
      
      console.log(`[Security] Checking URL for gambling content: ${hostname}${pathname}`);
      
      // Skip common non-gambling domains that might trigger false positives
      const safeDomains = [
        // Rhymes and poetry
        'nurseryrhyme', 'rhyme', 'rhymes', 'poetry', 'poem', 'poems', 'lyrics', 'songs', 'lullaby', 'lullabies',
        'nurseryrhymes', 'childrensongs', 'kidssongs', 'childrenpoems', 'kidspoems', 'storytime', 'storytimes',
        
        // Children's content
        'kids', 'children', 'toddler', 'preschool', 'kindergarten', 'elementary', 'primaryschool',
        'story', 'stories', 'fairytale', 'fairytales', 'fable', 'fables', 'bedtime', 'bedtimestory',
        
        // Education and learning
        'education', 'educational', 'learning', 'learn', 'teach', 'teacher', 'teaching', 'school', 'classroom',
        'homeschool', 'homeschooling', 'parenting', 'family', 'parent', 'mom', 'dad', 'grandma', 'grandpa',
        
        // Safe content platforms
        'youtube.com', 'youtu.be', 'vimeo.com', 'dailymotion.com', 'ted.com', 'khanacademy.org',
        'pbskids.org', 'sesamestreet.org', 'abcmouse.com', 'starfall.com', 'funbrain.com',
        'pbs.org', 'pbskids.org', 'pbslearningmedia.org', 'pbslearningmedia.com',
        'nationalgeographic.com', 'natgeokids.com', 'disney.com', 'disneyjunior.com',
        'nickjr.com', 'nickelodeon.com', 'nickelodeonjunior.com', 'cartoonnetwork.com',
        'cocomelon.com', 'pinkfong.com', 'supersimple.com', 'mothergooseclub.com',
        'britishcouncil.org/learnenglish/kids', 'learnenglishkids.britishcouncil.org',
        'storynory.com', 'stories.audible.com', 'vooks.com', 'epic.com', 'abcmouse.com',
        'readingiq.com', 'homerlearning.com', 'khanacademykids.org', 'duolingo.com/kids',
        'turtlediary.com', 'funbrain.com', 'funbrainjr.com', 'highlightskids.com',
        'pbskids.org', 'pbskids.org/video', 'pbskids.org/games', 'pbskids.org/apps',
        'sesamestreet.org', 'sesamestreet.org/games', 'sesamestreet.org/videos',
        'abcya.com', 'abcya.com/games', 'abcya.com/grades', 'abcya.xyz',
        'starfall.com', 'starfall.com/h', 'starfall.com/h2', 'starfall.com/pay/membership',
        'funbrain.com', 'funbrain.com/games', 'funbrain.com/books', 'funbrain.com/videos'
      ];
      
      // Check against safe domains first - more precise matching
      const isSafeDomain = safeDomains.some(domain => {
        // For full domains (containing dots), match exactly or as subdomain
        if (domain.includes('.')) {
          return hostname === domain || 
                 hostname.endsWith('.' + domain) ||
                 hostname.includes('/' + domain) ||
                 hostname.includes('.' + domain + '/') ||
                 pathname.includes(domain);
        }
        // For keywords, check in hostname or path
        return hostname.includes(domain) || pathname.includes(domain);
      });
      
      if (isSafeDomain) {
        console.log(`[Security] Allowing safe domain/content: ${hostname}${pathname}`);
        return false;
      }
      
      // Only block specific gambling TLDs, not all .games or similar
      const gamblingTLDs = [
        '.poker', '.bet', '.bingo', '.lotto', '.vegas', '.casino', '.sportbet', '.poker',
        '.bettings', '.poker', '.betting', '.poker', '.casino', '.poker', '.gambling', '.poker'
      ];
      
      // Check for gambling TLDs
      if (gamblingTLDs.some(tld => hostname.endsWith(tld))) {
        console.log(`[Security] Blocked gambling TLD: ${hostname}`);
        return true;
      }
      
      // More specific list of known gambling domains
      const gamblingDomains = [
        // Popular gambling sites
        '888.com', 'pokerstars.', 'williamhill.', 'bet365.', 'bwin.', 'unibet.', 'betfair.',
        'draftkings.', 'fanduel.', 'paddypower.', 'betway.', 'bovada.', 'ignitioncasino.',
        'betonline.', 'sportsbetting.', 'mybookie.', 'xbet.', 'betus.', 'gtbets.', 'heritagesports.',
        'bookmaker.', 'youwager.', 'sportsinteraction.', 'betcris.', 'pinnacle.', '5dimes.', 'betdsi.',
        'sportsbook.ag', 'betphoenix.', 'betmania.', 'betjamaica.', 'betcris.'
      ];
      
      // Only check for gambling terms in specific contexts
      const gamblingContexts = [
        // Paths that indicate gambling
        '/poker/', '/slots/', '/blackjack/', '/roulette/', '/baccarat/', '/craps/', '/keno/', '/bingo/',
        '/lottery/', '/sportsbook', '/casino/', '/livecasino/', '/live-casino/', '/live/dealer/',
        // Query parameters that indicate gambling
        '?game=', '?play=', '?casino=', '?bet=', '?poker=', '?slot=', '?bingo=', '?roulette='
      ];
      
      // Check for gambling domains
      const isGamblingDomain = gamblingDomains.some(domain => 
        hostname.includes(domain) || 
        (hostname + '/').includes(domain + '/') // Only match full domain segments
      );
      
      // Check for gambling contexts
      const hasGamblingContext = gamblingContexts.some(context => 
        pathname.includes(context) || 
        href.includes(context)
      );
      
      // Only block if we have both a gambling domain and gambling context
      // or if it's a known gambling domain with high confidence
      if (isGamblingDomain && hasGamblingContext) {
        console.log(`[Security] Blocked gambling site with high confidence: ${hostname}${pathname}`);
        return true;
      }
      
      // For less certain matches, we'll be more permissive
      if (isGamblingDomain) {
        console.log(`[Security] Allowing possible gambling site (low confidence): ${hostname}${pathname}`);
        return false;
      }
      
      // Check for gambling patterns but only in specific contexts
      const gamblingPatterns = [
        // High confidence patterns
        /\b(online[- ]?)?(casino|poker|bingo|blackjack|roulette|slots|baccarat|craps|keno|sportsbook)\b/i,
        /\b(play|bet|wager|gambl)(ing|e[dr]?|s)?\s+(for\s+)?(real\s+money|money|prizes|rewards|bonus)/i,
        /\b(free\s+)?(spins|play|bet|wager|bonus|deposit|sign[- ]?up|no\s+deposit)\b/i,
        /\b(welcome\s+)?(bonus|promo\s*code|free\s+spin|free\s+bet|no\s+deposit)\b/i
      ];
      
      // Only check patterns if we have some gambling context
      if (hasGamblingContext) {
        const matchesPattern = gamblingPatterns.some(pattern => 
          pattern.test(hostname) || pattern.test(pathname) || pattern.test(href)
        );
        
        if (matchesPattern) {
          console.log(`[Security] Blocked gambling pattern in URL: ${hostname}${pathname}`);
          return true;
        }
      }
      
      return false;
      
    } catch (e) {
      console.error('[Security] Error checking gambling site:', e);
      console.error('[Security] URL that caused error:', url);
      return false; // Default to allowing if there's an error
    }
  }
  
  // Add a domain to the user's ad blocklist
  addToAdBlocklist(domain) {
    try {
      const userDataPath = this.app.getPath('userData');
      const adBlockPath = path.join(userDataPath, 'user-ad-blocklist.json');
      
      let currentList = [];
      if (fs.existsSync(adBlockPath)) {
        currentList = JSON.parse(fs.readFileSync(adBlockPath, 'utf-8'));
      }
      
      if (!currentList.includes(domain)) {
        currentList.push(domain);
        fs.writeFileSync(adBlockPath, JSON.stringify(currentList, null, 2));
        this.adBlockList.push(domain);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Error adding to ad blocklist:', error);
      return false;
    }
  }
}

module.exports = SecurityFilter;
