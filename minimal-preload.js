// Minimal preload script for AgeLock browser
const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld(
  'api',
  {
    // Age verification methods
    setAge: (ageRange) => {
      console.log(`Preload: Setting age range: ${ageRange}`);
      return ipcRenderer.invoke('set-age', ageRange);
    },
    getAge: () => {
      console.log('Preload: Getting age range');
      return ipcRenderer.invoke('get-age');
    },
    resetAge: () => {
      console.log('Preload: Resetting age');
      return ipcRenderer.invoke('reset-age');
    },
    
    // PIN management methods
    getPin: () => {
      console.log('Preload: Getting PIN status');
      return ipcRenderer.invoke('get-pin');
    },
    setPin: (pinData) => {
      console.log('Preload: Setting new PIN');
      return ipcRenderer.invoke('set-pin', pinData);
    },
    verifyPin: (pinData) => {
      console.log('Preload: Verifying PIN');
      return ipcRenderer.invoke('verify-pin', pinData);
    },
    
    // Security question management methods
    getSecurityQuestions: () => {
      console.log('Preload: Getting security questions');
      return ipcRenderer.invoke('get-security-questions');
    },
    setSecurityQuestion: (questionData) => {
      console.log('Preload: Setting security question');
      return ipcRenderer.invoke('set-security-question', questionData);
    },
    storeSecurityQuestions: (questions) => {
      console.log('Preload: Storing security questions');
      return ipcRenderer.invoke('store-security-questions', questions);
    },
    verifySecurityQuestion: (questionData) => {
      console.log('Preload: Verifying security question');
      return ipcRenderer.invoke('verify-security-question', questionData);
    },
    
    // Content filtering methods
    filterContent: (content) => {
      console.log('Preload: Filtering content');
      return ipcRenderer.invoke('filter-content', content);
    },
    filterText: (text) => {
      console.log(`Preload: Filtering text: ${text}`);
      return ipcRenderer.invoke('filter-content', { text });
    },
    filterUrl: (url) => {
      console.log(`Preload: Filtering URL: ${url}`);
      return ipcRenderer.invoke('filter-content', { url });
    }
  }
);
