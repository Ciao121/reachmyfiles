const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
	selectFolder: () => ipcRenderer.invoke('select-folder'),
	removeShare: (uuid, permanent) => ipcRenderer.invoke('remove-share', uuid, permanent),
	toggleShare: (uuid, enabled) => ipcRenderer.invoke('toggle-share', uuid, enabled),
	onSharesUpdated: (callback) => ipcRenderer.on('shares-updated', (event, data) => callback(data)),
	onUsersUpdated: (callback) => ipcRenderer.on('users-updated', (event, data) => callback(data)),
	checkForUpdates: () => ipcRenderer.send('check-for-updates'),
	onShowUpdateCheckDialog: (callback) => ipcRenderer.on('show-update-check-dialog', callback),
	onUpdateAvailable: (callback) => ipcRenderer.on('update-available', callback),
	onUpdateDownloaded: (callback) => ipcRenderer.on('update-downloaded', callback),
	onUpdateError: (callback) => ipcRenderer.on('update-error', (event, err) => callback(err)),
});
