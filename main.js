const { app, BrowserWindow, dialog, ipcMain, Menu, Tray, nativeImage } = require('electron');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const WebSocket = require('ws');
const crypto = require('crypto');
const EC = require('elliptic').ec;
const { autoUpdater } = require('electron-updater');

app.setName('reachmyfiles');
app.commandLine.appendSwitch('disable-renderer-backgrounding');
let wsHeartbeatInterval = null;
let pendingRegistrations = [];
let activeStreams = {};
let handshake = {};
let mainWindow;
let tray = null;
let isQuiting = false;
let sharedFolders = [];
let ws = null;

const STORE_PATH = path.join(app.getPath('userData'), 'shared_folders.json');
let activeUsers = {};
let downloadIdToUuid = {};

function log(...args) {
	const now = new Date().toISOString().replace('T', ' ').replace('Z','');
	console.log(`[${now}]`, ...args);
}

function cleanupStream(downloadId, origin='?') {
	if (activeStreams[downloadId]) {
		try {
			const s = activeStreams[downloadId];
			if (s && !s.destroyed) s.destroy();
			if (s) s.removeAllListeners();
		} catch (e) {
			log('[CLIENT] Error in cleanupStream:', e);
		}
		delete activeStreams[downloadId];
		const err = new Error();
		const stackShort = (err.stack || '').split('\n').slice(2,6).join('\n');
		log(`[DEBUG][${downloadId}] cleanupStream CALLED by: ${origin}\n${stackShort}`);
	}
	if (chunkBufferCount[downloadId] !== undefined) delete chunkBufferCount[downloadId];
	if (backpressureWaiters[downloadId]) delete backpressureWaiters[downloadId];
	if (downloadIdToUuid[downloadId]) delete downloadIdToUuid[downloadId];
}

function loadShares() {
	try {
		sharedFolders = JSON.parse(fs.readFileSync(STORE_PATH, 'utf-8'));
	} catch {
		sharedFolders = [];
	}
}
function saveShares() {
	fs.writeFileSync(STORE_PATH, JSON.stringify(sharedFolders, null, 2));
}

function getFolder(uuid) {
	return sharedFolders.find(x => x.uuid === uuid);
}

const ec = new EC('p256');
let keyPairs = {};

async function doECDHHandshakeFor(uuid, browserPubKeyArr, sendPubKeyCb) {
	let ecKey = keyPairs[uuid];
	if (!ecKey) {
		ecKey = ec.genKeyPair();
		keyPairs[uuid] = ecKey;
	}
	const peer = ec.keyFromPublic(browserPubKeyArr, 'array');
	const shared = ecKey.derive(peer.getPublic());
	const sharedBuf = Buffer.from(shared.toArray('be', 32));
	const sharedAESKey = crypto.createHash('sha256').update(sharedBuf).digest();
	handshake[uuid] = { ec: ecKey, aes: sharedAESKey, ready: true };
	const myPubKey = ecKey.getPublic('array');
	sendPubKeyCb(Array.from(myPubKey));
	log(`[E2EE] Handshake completed for uuid ${uuid}`);
	console.log('[CLIENT] AES KEY:', sharedAESKey.toString('hex'));
}

function encryptPayload(uuid, obj) {
	const key = handshake[uuid] && handshake[uuid].aes;
	if (!key) throw new Error('AES key not ready');
	const iv = crypto.randomBytes(12);
	const plaintext = Buffer.from(JSON.stringify(obj));
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
	const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();
	const combined = Buffer.concat([iv, encrypted, tag]);
	return combined.toString('base64');
}

function encryptChunk(uuid, chunk) {
	const key = handshake[uuid] && handshake[uuid].aes;
	if (!key) throw new Error('AES key not ready (chunk)');
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
	const encrypted = Buffer.concat([cipher.update(chunk), cipher.final()]);
	const tag = cipher.getAuthTag();
	const combined = Buffer.concat([iv, encrypted, tag]);
	return combined.toString('base64');
}

async function decryptPayload(uuid, base64) {
	const key = handshake[uuid] && handshake[uuid].aes;
	if (!key) throw new Error('AES key not ready for decrypt');
	const buf = Buffer.from(base64, 'base64');
	const iv = buf.slice(0, 12);
	const tag = buf.slice(buf.length - 16);
	const ciphertext = buf.slice(12, buf.length - 16);
	const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
	decipher.setAuthTag(tag);
	let decrypted = decipher.update(ciphertext);
	decrypted = Buffer.concat([decrypted, decipher.final()]);
	return JSON.parse(decrypted.toString());
}

function sendEncrypted(uuid, obj) {
	const key = handshake[uuid] && handshake[uuid].aes;
	if (!key) throw new Error('AES key not ready');
	const iv = crypto.randomBytes(12);
	const plaintext = Buffer.from(JSON.stringify(obj));
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
	const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();
	const base64 = Buffer.concat([iv, encrypted, tag]).toString('base64');
	ws.send(JSON.stringify({
		type: 'encrypted',
		uuid,
		payload: base64
	}));
}

const downloadChunkAckEvery = 8;
let chunkBufferCount = {};
const MAX_CHUNKS_IN_FLIGHT = 32;
let backpressureWaiters = {};
let downloadReady = {};
let pendingDownloadRequests = {};

function connectToServer() {
	ws = new WebSocket('wss://www.reachmyfiles.com:443/ws/');
	log('[CLIENT] Creating WebSocket...');

	ws.on('open', () => {
		log('[CLIENT] WebSocket open!');
		sharedFolders.filter(x => x.enabled && !x.removed).forEach(share => registerShare(share.uuid));
		pendingRegistrations.forEach(uuid => {
			ws.send(JSON.stringify({ type: 'register', uuid }));
		});
		pendingRegistrations = [];
		clearInterval(wsHeartbeatInterval);
		wsHeartbeatInterval = setInterval(() => {
			if (ws && ws.readyState === WebSocket.OPEN) {
				try { ws.send(JSON.stringify({ type: 'ping' })); } catch (e) {}
			}
		}, 20000);
	});

	ws.on('message', async (message) => {
		let data;
		try {
			data = typeof message === 'string' ? JSON.parse(message) : JSON.parse(message.toString());
		} catch (err) {
			console.log('[CLIENT] Invalid JSON message:', message);
			return;
		}

		if (data.type === "publicKey" && data.payload && data.uuid) {
			console.log('[CLIENT] Received browser publicKey for handshake!');
			await doECDHHandshakeFor(
				data.uuid,
				data.payload,
				(pubKeyArray) => ws.send(JSON.stringify({
					type: "publicKey",
					uuid: data.uuid,
					payload: pubKeyArray
				}))
			);
			return;
		}

		if (
			data.type === 'encrypted' &&
			data.uuid &&
			handshake[data.uuid] &&
			handshake[data.uuid].ready &&
			typeof data.payload === 'string'
		) {
			try {
				const payload = await decryptPayload(data.uuid, data.payload);

				if (payload.action === 'list') {
					const folder = getFolder(data.uuid);
					if (folder) {
						let targetDir = folder.path;
						if (payload.path && payload.path !== '/' && payload.path !== '') {
							targetDir = path.join(folder.path, payload.path);
						}
						const files = [];
						const dirs = [];
						const sizes = {};
						fs.readdirSync(targetDir).forEach(f => {
							const stat = fs.statSync(path.join(targetDir, f));
							if (stat.isFile()) {
								files.push(f);
								sizes[f] = stat.size;
							}
							else if (stat.isDirectory()) dirs.push(f);
						});
						sendEncrypted(data.uuid, {
							action: 'list_response',
							files,
							dirs,
							path: payload.path || '/',
							sizes
						});
					} else {
						sendEncrypted(data.uuid, { action: 'error', message: 'Folder not found' });
					}
				}
				else if (payload.action === 'download' && payload.file && payload.downloadId) {
					const folder = getFolder(data.uuid);
					if (!folder) {
						sendEncrypted(data.uuid, { action: 'error', message: 'Folder not found' });
						return;
					}
					let targetDir = folder.path;
					if (payload.path && payload.path !== '/' && payload.path !== '') {
						targetDir = path.join(folder.path, payload.path);
					}
					const filePath = path.join(targetDir, payload.file);
					if (!fs.existsSync(filePath)) {
						sendEncrypted(data.uuid, { action: 'error', message: 'File not found' });
						return;
					}
					const stats = fs.statSync(filePath);
					log(`[DEBUG][${payload.downloadId}] Requested file: ${filePath} - SIZE: ${stats.size} bytes`);
					sendEncrypted(data.uuid, {
						action: 'file_info',
						file: payload.file,
						downloadId: payload.downloadId,
						fileSize: stats.size
					});
					pendingDownloadRequests[payload.downloadId] = { folder, targetDir, filePath, payload, uuid: data.uuid };
				}
				else if (payload.action === 'download_ready' && payload.downloadId) {
					downloadReady[payload.downloadId] = true;
					const pending = pendingDownloadRequests[payload.downloadId];
					if (pending) {
						startDownloadStream(pending.uuid, pending.filePath, pending.payload.downloadId, pending.payload.file);
						delete pendingDownloadRequests[payload.downloadId];
					}
				}
				else if (payload.action === 'chunk_ack' && payload.downloadId && chunkBufferCount[payload.downloadId] !== undefined) {
					chunkBufferCount[payload.downloadId] = Math.max(0, chunkBufferCount[payload.downloadId] - downloadChunkAckEvery);
					if (backpressureWaiters[payload.downloadId]) {
						while (backpressureWaiters[payload.downloadId].length && chunkBufferCount[payload.downloadId] < MAX_CHUNKS_IN_FLIGHT) {
							backpressureWaiters[payload.downloadId].shift()?.();
						}
					}
				}
				else if (payload.action === 'cancel_download' && payload.downloadId) {
					handleDownloadEndByDownloadId(payload.downloadId, 'browser cancel_download');
					delete chunkBufferCount[payload.downloadId];
				}
				else if (payload.action === 'error' && payload.downloadId) {
					handleDownloadEndByDownloadId(payload.downloadId, 'browser error');
					delete chunkBufferCount[payload.downloadId];
				}
			} catch (err) {
				log('[DECRYPT ERROR]', err.message);
			}
		}
	});

	ws.on('close', () => {
		clearInterval(wsHeartbeatInterval);
		setTimeout(connectToServer, 3000);
	});
	ws.on('error', err => {
		clearInterval(wsHeartbeatInterval);
	});
}

async function startDownloadStream(uuid, filePath, downloadId, fileName) {
	const stats = fs.statSync(filePath);
	const fileSizeExpected = stats.size;
	const chunkSize = 64 * 1024;
	const expectedChunks = Math.ceil(fileSizeExpected / chunkSize);

	let chunkIndex = 0;
	let totalBytesSent = 0;
	chunkBufferCount[downloadId] = 0;
	backpressureWaiters[downloadId] = [];

	const stream = fs.createReadStream(filePath, { highWaterMark: chunkSize });
	activeStreams[downloadId] = stream;
	downloadIdToUuid[downloadId] = uuid;

	if (!activeUsers[uuid]) activeUsers[uuid] = 0;
	activeUsers[uuid]++;
	mainWindow && mainWindow.webContents.send('users-updated', { uuid, count: activeUsers[uuid] });

	async function onDownloadEnd() {
		if (activeUsers[uuid]) activeUsers[uuid]--;
		if (activeUsers[uuid] < 0) activeUsers[uuid] = 0;
		mainWindow && mainWindow.webContents.send('users-updated', { uuid, count: activeUsers[uuid] });
		if (downloadIdToUuid[downloadId]) delete downloadIdToUuid[downloadId];
	}

	stream.on('close', onDownloadEnd);
	stream.on('error', onDownloadEnd);

	try {
		for await (const chunk of stream) {
			while (chunkBufferCount[downloadId] >= MAX_CHUNKS_IN_FLIGHT) {
				await new Promise(resolve => {
					backpressureWaiters[downloadId].push(resolve);
				});
			}
			const encChunk = encryptChunk(uuid, chunk);
			sendEncrypted(uuid, {
				action: 'file_chunk',
				chunk: encChunk,
				downloadId: downloadId,
				chunkIndex
			});
			chunkBufferCount[downloadId]++;
			chunkIndex++;
			totalBytesSent += chunk.length;
		}
		sendEncrypted(uuid, {
			action: 'file_end',
			downloadId: downloadId
		});
		cleanupStream(downloadId, 'stream.end');
		delete chunkBufferCount[downloadId];
		await onDownloadEnd();
	} catch (err) {
		cleanupStream(downloadId, 'stream.error');
		sendEncrypted(uuid, {
			action: 'error',
			message: err.message,
			downloadId: downloadId
		});
		delete chunkBufferCount[downloadId];
		await onDownloadEnd();
	}
}

function handleDownloadEndByDownloadId(downloadId, origin) {
	let uuid = downloadIdToUuid[downloadId];
	if (!uuid && activeStreams[downloadId] && activeStreams[downloadId].uuid) {
		uuid = activeStreams[downloadId].uuid;
	}
	if (uuid && activeUsers[uuid]) {
		activeUsers[uuid]--;
		if (activeUsers[uuid] < 0) activeUsers[uuid] = 0;
		mainWindow && mainWindow.webContents.send('users-updated', { uuid, count: activeUsers[uuid] });
	}
	cleanupStream(downloadId, origin || 'handleDownloadEnd');
}

ipcMain.handle('select-folder', async () => {
	const result = await dialog.showOpenDialog(mainWindow, { properties: ['openDirectory'] });
	if (!result.canceled && result.filePaths.length > 0) {
		const folder = result.filePaths[0];
		let existing = sharedFolders.find(x => x.path === folder);
		let uuid;
		if (existing) {
			uuid = existing.uuid;
			existing.enabled = true;
			existing.removed = false;
		} else {
			uuid = uuidv4();
			sharedFolders.push({ uuid, path: folder, enabled: true, removed: false });
		}
		saveShares();
		registerShare(uuid);
		mainWindow.webContents.send('shares-updated', sharedFolders);
		return { uuid, path: folder };
	}
	return null;
});

ipcMain.handle('remove-share', async (event, uuid, permanent) => {
	const idx = sharedFolders.findIndex(x => x.uuid === uuid);
	if (idx !== -1) {
		if (permanent) {
			sharedFolders.splice(idx, 1);
		} else {
			sharedFolders[idx].removed = true;
			sharedFolders[idx].enabled = false;
		}
		saveShares();
		mainWindow.webContents.send('shares-updated', sharedFolders);
		if (ws && ws.readyState === WebSocket.OPEN) {
			ws.send(JSON.stringify({ type: 'unregister', uuid }));
		}
	}
});

ipcMain.handle('toggle-share', async (event, uuid, enabled) => {
	let share = sharedFolders.find(x => x.uuid === uuid);
	if (share) {
		share.enabled = enabled;
		saveShares();
		if (enabled) {
			registerShare(uuid);
		} else {
			if (ws && ws.readyState === WebSocket.OPEN) {
				ws.send(JSON.stringify({ type: 'unregister', uuid }));
			}
		}
		mainWindow.webContents.send('shares-updated', sharedFolders);
	}
});

ipcMain.on('check-for-updates', () => {
	autoUpdater.checkForUpdates();
});

function createWindow() {
	mainWindow = new BrowserWindow({
		width: 600,
		height: 440,
		minWidth: 480,
		minHeight: 340,
		icon: path.join(__dirname, 'favicons', 'favicon.ico'),
		webPreferences: {
			preload: path.join(__dirname, 'preload.js'),
			contextIsolation: true,
		},
		resizable: true,
		show: false,
		title: 'reachmyfiles'
	});

	mainWindow.setMenu(null);
	mainWindow.removeMenu();

	mainWindow.webContents.on('before-input-event', (event, input) => {
		if ((input.control || input.meta) && input.key.toLowerCase() === 'i') event.preventDefault();
		if ((input.control || input.meta) && input.key.toLowerCase() === 'shift' && input.key.toLowerCase() === 'i') event.preventDefault();
	});
	mainWindow.webContents.on('devtools-opened', () => {
		mainWindow.webContents.closeDevTools();
	});

	let splash = new BrowserWindow({
		width: 300,
		height: 300,
		frame: false,
		alwaysOnTop: true,
		transparent: true,
		resizable: false,
		skipTaskbar: true,
	});
	splash.loadFile(path.join(__dirname, 'images', 'splash.html'));
	mainWindow.loadFile('desktopindex.html');

	mainWindow.once('ready-to-show', () => {
		setTimeout(() => {
			splash.close();
			mainWindow.show();
			mainWindow.webContents.send('show-update-check-dialog');
		}, 1200);
	});

	const trayIconPath = path.join(__dirname, 'favicons', 'favicon.ico');
	tray = new Tray(nativeImage.createFromPath(trayIconPath));
	tray.setToolTip('reachmyfiles');
	const contextMenu = Menu.buildFromTemplate([
		{
			label: 'Open',
			click: () => {
				mainWindow.show();
				mainWindow.setSkipTaskbar(false);
			}
		},
		{
			label: 'Quit',
			click: () => {
				const response = dialog.showMessageBoxSync(mainWindow, {
					type: 'warning',
					buttons: ['Quit', 'Cancel'],
					defaultId: 1,
					title: 'Confirm Exit',
					message: 'Are you sure you want to quit?',
					detail: 'All active file shares will be interrupted.',
					cancelId: 1,
					noLink: true,
				});
				if (response === 0) {
					isQuiting = true;
					app.quit();
				}
			}
		}
	]);
	tray.setContextMenu(contextMenu);

	tray.on('click', () => {
		mainWindow.show();
		mainWindow.setSkipTaskbar(false);
	});

	mainWindow.on('minimize', function (event) {
		event.preventDefault();
		mainWindow.hide();
		mainWindow.setSkipTaskbar(true);
		tray.displayBalloon && tray.displayBalloon({
			icon: trayIconPath,
			title: 'reachmyfiles',
			content: 'App is running in the background.'
		});
	});

	mainWindow.on('close', function (event) {
		if (!isQuiting) {
			event.preventDefault();
			const response = dialog.showMessageBoxSync(mainWindow, {
				type: 'warning',
				buttons: ['Quit', 'Cancel'],
				defaultId: 1,
				title: 'Confirm Exit',
				message: 'Are you sure you want to quit?',
				detail: 'All active file shares will be interrupted.',
				cancelId: 1,
				noLink: true,
			});
			if (response === 0) {
				isQuiting = true;
				app.quit();
			}
		}
	});

	mainWindow.webContents.on('did-finish-load', () => {
		mainWindow.webContents.send('shares-updated', sharedFolders);
	});
}

function registerShare(uuid) {
	if (ws && ws.readyState === WebSocket.OPEN) {
		log(`[CLIENT] Sending registration for uuid: ${uuid}`);
		ws.send(JSON.stringify({ type: 'register', uuid }));
	} else {
		log(`[CLIENT] Queue registration for uuid: ${uuid} (ws not ready)`);
		pendingRegistrations.push(uuid);
	}
}

app.whenReady().then(() => {
	loadShares();
	createWindow();
	connectToServer();

	autoUpdater.checkForUpdates();

	autoUpdater.on('update-available', () => {
		if (mainWindow) mainWindow.webContents.send('update-available');
	});

	autoUpdater.on('update-downloaded', () => {
		if (mainWindow) mainWindow.webContents.send('update-downloaded');
	});

	autoUpdater.on('error', (err) => {
		if (mainWindow) mainWindow.webContents.send('update-error', err == null ? "unknown" : err.message);
	});
});

ipcMain.on('check-for-updates', () => {
	autoUpdater.checkForUpdates();
});
