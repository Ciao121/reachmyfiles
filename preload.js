const { contextBridge, ipcRenderer } = require('electron');
const path = require('path');
const fs = require('fs');

function getAppVersion() {
	try {
		const prodPath = path.join(process.resourcesPath, 'app', 'package.json');
		if (fs.existsSync(prodPath)) {
			const pkg = JSON.parse(fs.readFileSync(prodPath, 'utf-8'));
			return pkg.version;
		}
		const devPath = path.resolve(__dirname, 'package.json');
		if (fs.existsSync(devPath)) {
			const pkg = JSON.parse(fs.readFileSync(devPath, 'utf-8'));
			return pkg.version;
		}
	} catch (e) {
		console.log('getAppVersion error:', e);
	}
	return '';
}

contextBridge.exposeInMainWorld('electronAPI', {
	selectFolder: () => ipcRenderer.invoke('select-folder'),
	removeShare: (uuid, permanent) => ipcRenderer.invoke('remove-share', uuid, permanent),
	toggleShare: (uuid, enabled) => ipcRenderer.invoke('toggle-share', uuid, enabled),
	onSharesUpdated: (callback) => ipcRenderer.on('shares-updated', (event, data) => callback(data)),
	onUsersUpdated: (callback) => ipcRenderer.on('users-updated', (event, data) => callback(data)),
	checkForUpdates: () => ipcRenderer.send('check-for-updates'),
	onUpdateAvailable: (callback) => ipcRenderer.on('update-available', callback),
	onUpdateDownloaded: (callback) => ipcRenderer.on('update-downloaded', callback),
	onUpdateError: (callback) => ipcRenderer.on('update-error', (event, err) => callback(err)),
	getAppVersion: () => getAppVersion(),
	quitAndInstall: () => ipcRenderer.send('quit-and-install'),
});
