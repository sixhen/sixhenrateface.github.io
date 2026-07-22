/**
 * DocSecure - Core Application
 * Hệ thống quản lý tài liệu bảo mật cao
 * @version 2.0.0
 */

// ============================================
// CONFIGURATION
// ============================================
const CONFIG = {
    appName: 'DocSecure',
    version: '2.0.0',
    storagePrefix: 'docsecure_',
    sessionTimeout: 3600000,
    maxLoginAttempts: 5,
    blockDuration: 300000,
    pageSize: 12,
    maxFileSize: 10485760,
    allowedTypes: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'png', 'txt'],
    watermarkOpacity: 0.06,
    watermarkSpacing: 200,
    adminEmail: 'admin@docsecure.com',
    adminPassword: 'Admin@2026#Secure',
    tokenExpiry: 600000,
    cacheTTL: 3600000,
    backupPrefix: 'docsecure_backup_'
};

// ============================================
// DATABASE
// ============================================
class Database {
    constructor() {
        this.db = null;
        this.stores = [
            'users', 'documents', 'purchases', 'views', 'sessions', 
            'categories', 'ipLogs', 'tokens', 'vouchers', 'orders',
            'wishlist', 'notifications', 'auditLogs', 'paymentSettings',
            'readingProgress', 'backups'
        ];
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('DocSecureDB', 4);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                resolve(this.db);
            };
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                this.stores.forEach(name => {
                    if (!db.objectStoreNames.contains(name)) {
                        const store = db.createObjectStore(name, { keyPath: 'id' });
                        this.createIndexes(store, name);
                    }
                });
            };
        });
    }

    createIndexes(store, name) {
        const indexes = {
            users: ['email', 'username', 'fingerprint', 'status'],
            documents: ['category', 'uploadDate', 'price', 'ownerId', 'status'],
            purchases: ['userId', 'documentId', 'purchaseDate', 'status'],
            views: ['userId', 'documentId', 'viewDate'],
            sessions: ['userId', 'fingerprint', 'expires'],
            tokens: ['userId', 'documentId', 'expires'],
            vouchers: ['code', 'userId', 'used', 'expires'],
            orders: ['userId', 'status', 'createdAt'],
            wishlist: ['userId', 'documentId'],
            notifications: ['userId', 'read', 'createdAt'],
            auditLogs: ['userId', 'action', 'createdAt'],
            readingProgress: ['userId', 'documentId']
        };
        
        if (indexes[name]) {
            indexes[name].forEach(index => {
                const unique = ['email', 'username', 'code'].includes(index);
                store.createIndex(index, index, { unique });
            });
        }
    }

    async add(store, data) {
        return this.transaction(store, 'readwrite', s => s.add(data));
    }

    async update(store, data) {
        return this.transaction(store, 'readwrite', s => s.put(data));
    }

    async delete(store, id) {
        return this.transaction(store, 'readwrite', s => s.delete(id));
    }

    async get(store, id) {
        return this.transaction(store, 'readonly', s => s.get(id));
    }

    async getAll(store) {
        return this.transaction(store, 'readonly', s => s.getAll());
    }

    async query(store, index, value) {
        return this.transaction(store, 'readonly', s => s.index(index).getAll(value));
    }

    async queryRange(store, index, range) {
        return this.transaction(store, 'readonly', s => s.index(index).getAll(range));
    }

    transaction(store, mode, callback) {
        return new Promise((resolve, reject) => {
            if (!this.db) {
                reject(new Error('Database not initialized'));
                return;
            }
            const tx = this.db.transaction([store], mode);
            const request = callback(tx.objectStore(store));
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2, 8);
    }

    async clear(store) {
        const items = await this.getAll(store);
        for (const item of items) {
            await this.delete(store, item.id);
        }
    }
}

// ============================================
// UTILITIES
// ============================================
const Utils = {
    getFingerprint() {
        const components = [
            navigator.userAgent,
            navigator.language,
            navigator.platform,
            screen.width,
            screen.height,
            screen.colorDepth,
            new Date().getTimezoneOffset(),
            navigator.hardwareConcurrency || 0,
            navigator.deviceMemory || 0
        ];
        const str = components.join('|');
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash = hash & hash;
        }
        return 'fp_' + hash.toString(36).padStart(8, '0');
    },

    hash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash = hash & hash;
        }
        return 'h_' + hash.toString(36);
    },

    formatDate(date) {
        if (!date) return 'N/A';
        const d = new Date(date);
        return d.toLocaleDateString('vi-VN') + ' ' + d.toLocaleTimeString('vi-VN');
    },

    formatCurrency(amount) {
        if (!amount || amount === 0) return 'Miễn phí';
        return amount.toLocaleString('vi-VN') + 'đ';
    },

    generateWatermark(username, email, id) {
        const now = new Date().toISOString();
        return `${username} | ${email} | ${id} | ${now}`;
    },

    generateToken() {
        return 'tk_' + Math.random().toString(36).substr(2, 16) + '_' + Date.now().toString(36);
    },

    generateVoucherCode() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let code = '';
        for (let i = 0; i < 8; i++) {
            code += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return code;
    },

    supportsScreenProtection() {
        return !!(navigator.mediaDevices?.getDisplayMedia || window.PresentationRequest);
    },

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    throttle(fn, delay) {
        let lastCall = 0;
        return function(...args) {
            const now = Date.now();
            if (now - lastCall >= delay) {
                lastCall = now;
                fn.apply(this, args);
            }
        };
    },

    debounce(fn, delay) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => fn.apply(this, args), delay);
        };
    },

    truncate(text, length = 100) {
        if (!text) return '';
        return text.length > length ? text.substring(0, length) + '...' : text;
    },

    generateQR(data) {
        // Simulate QR code generation (in production, use a QR library)
        return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(data)}`;
    }
};

// ============================================
// AUTH SYSTEM
// ============================================
class Auth {
    constructor(db) {
        this.db = db;
        this.currentUser = null;
        this.sessionKey = CONFIG.storagePrefix + 'session';
        this.fingerprint = Utils.getFingerprint();
        this.loginAttempts = {};
        this.init();
    }

    async init() {
        const session = localStorage.getItem(this.sessionKey);
        if (session) {
            try {
                const data = JSON.parse(session);
                if (data.expires > Date.now() && data.fingerprint === this.fingerprint) {
                    this.currentUser = data.user;
                    this.updateUI();
                    this.checkNotifications();
                    return;
                }
                this.logout('Phiên đăng nhập đã hết hạn hoặc thiết bị không khớp');
            } catch (e) {
                this.logout();
            }
        }
        this.updateUI();
    }

    async login(email, password) {
        if (this.isBlocked(email)) {
            throw new Error('Tài khoản bị khóa tạm thời. Vui lòng thử lại sau 5 phút.');
        }

        try {
            const users = await this.db.getAll('users');
            const user = users.find(u => u.email === email && u.password === Utils.hash(password));
            
            if (!user) {
                this.recordAttempt(email);
                throw new Error('Email hoặc mật khẩu không đúng');
            }

            if (user.status === 'blocked') {
                throw new Error('Tài khoản đã bị khóa. Vui lòng liên hệ quản trị viên.');
            }

            const currentFingerprint = this.fingerprint;
            if (user.boundFingerprint && user.boundFingerprint !== currentFingerprint) {
                await this.db.add('ipLogs', {
                    id: this.db.generateId(),
                    userId: user.id,
                    email: user.email,
                    fingerprint: currentFingerprint,
                    expectedFingerprint: user.boundFingerprint,
                    timestamp: new Date().toISOString(),
                    type: 'fp_mismatch'
                });
                throw new Error('Thiết bị không khớp với thiết bị đã đăng ký.');
            }

            if (!user.boundFingerprint) {
                user.boundFingerprint = currentFingerprint;
                user.boundDate = new Date().toISOString();
                await this.db.update('users', user);
            }

            const session = {
                id: this.db.generateId(),
                userId: user.id,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role || 'user',
                    avatar: user.avatar
                },
                fingerprint: currentFingerprint,
                expires: Date.now() + CONFIG.sessionTimeout,
                loginTime: new Date().toISOString()
            };

            localStorage.setItem(this.sessionKey, JSON.stringify(session));
            await this.db.add('sessions', session);

            // Audit log
            await this.db.add('auditLogs', {
                id: this.db.generateId(),
                userId: user.id,
                action: 'login',
                details: `User ${user.username} logged in`,
                ip: currentFingerprint,
                createdAt: new Date().toISOString()
            });

            this.currentUser = session.user;
            this.clearAttempts(email);
            this.updateUI();
            this.checkNotifications();

            return session.user;
        } catch (error) {
            throw error;
        }
    }

    async register(userData) {
        try {
            const users = await this.db.getAll('users');
            if (users.find(u => u.email === userData.email)) {
                throw new Error('Email đã được sử dụng');
            }
            if (users.find(u => u.username === userData.username)) {
                throw new Error('Tên đăng nhập đã được sử dụng');
            }

            const newUser = {
                id: this.db.generateId(),
                username: userData.username,
                email: userData.email,
                password: Utils.hash(userData.password),
                fullName: userData.fullName || userData.username,
                role: 'user',
                status: 'active',
                avatar: userData.avatar || null,
                boundFingerprint: null,
                boundDate: null,
                createdAt: new Date().toISOString(),
                lastLogin: null,
                permissions: [],
                stats: { totalPurchases: 0, totalSpent: 0, documentsViewed: 0 },
                preferences: {
                    theme: 'light',
                    notifications: true,
                    autoSave: true
                }
            };

            await this.db.add('users', newUser);
            
            // Audit log
            await this.db.add('auditLogs', {
                id: this.db.generateId(),
                userId: newUser.id,
                action: 'register',
                details: `New user registered: ${newUser.username}`,
                createdAt: new Date().toISOString()
            });

            return await this.login(userData.email, userData.password);
        } catch (error) {
            throw error;
        }
    }

    logout(message = null) {
        if (this.currentUser) {
            this.db.getAll('sessions').then(sessions => {
                const session = sessions.find(s => s.userId === this.currentUser.id);
                if (session) this.db.delete('sessions', session.id);
            });
        }
        localStorage.removeItem(this.sessionKey);
        this.currentUser = null;
        this.updateUI();
        if (message) {
            app.showToast(message, 'warning');
        }
    }

    isBlocked(email) {
        const attempts = this.loginAttempts[email];
        if (!attempts) return false;
        if (Date.now() - attempts.firstAttempt > CONFIG.blockDuration) {
            delete this.loginAttempts[email];
            return false;
        }
        return attempts.count >= CONFIG.maxLoginAttempts;
    }

    recordAttempt(email) {
        if (!this.loginAttempts[email]) {
            this.loginAttempts[email] = { count: 0, firstAttempt: Date.now() };
        }
        this.loginAttempts[email].count++;
    }

    clearAttempts(email) {
        delete this.loginAttempts[email];
    }

    async checkNotifications() {
        if (!this.currentUser) return;
        const notifs = await this.db.query('notifications', 'userId', this.currentUser.id);
        const unread = notifs.filter(n => !n.read);
        const badge = document.getElementById('notifBadge');
        if (badge) {
            badge.textContent = unread.length;
            badge.style.display = unread.length > 0 ? 'inline' : 'none';
        }
    }

    updateUI() {
        const userMenu = document.getElementById('userMenu');
        if (!userMenu) return;

        if (this.currentUser) {
            const avatar = this.currentUser.avatar || 'assets/images/default-avatar.png';
            userMenu.innerHTML = `
                <div class="user-info" onclick="document.querySelector('.user-dropdown').classList.toggle('show')">
                    <img src="${avatar}" alt="${this.currentUser.username}" onerror="this.src='assets/images/default-avatar.png'">
                    <span class="username">${this.currentUser.username}</span>
                    <ul class="user-dropdown">
                        <li><a href="#" onclick="app.navigate('profile')"><i class="fas fa-user"></i> Hồ sơ</a></li>
                        <li><a href="#" onclick="app.navigate('purchases')"><i class="fas fa-book"></i> Tài liệu đã mua</a></li>
                        <li><a href="#" onclick="app.navigate('wishlist')"><i class="fas fa-heart"></i> Yêu thích</a></li>
                        <li><a href="#" onclick="app.navigate('view-history')"><i class="fas fa-history"></i> Lịch sử xem</a></li>
                        ${this.currentUser.role === 'admin' ? `
                            <li class="divider"></li>
                            <li><a href="admin.html"><i class="fas fa-shield-alt"></i> Quản trị</a></li>
                        ` : ''}
                        <li class="divider"></li>
                        <li><a href="#" onclick="app.auth.logout()" style="color:var(--danger);">
                            <i class="fas fa-sign-out-alt"></i> Đăng xuất
                        </a></li>
                    </ul>
                </div>
            `;
            
            document.querySelectorAll('.admin-only').forEach(el => {
                el.style.display = this.currentUser.role === 'admin' ? '' : 'none';
            });
        } else {
            userMenu.innerHTML = `
                <a href="#" onclick="app.navigate('login')" class="btn-login">Đăng nhập</a>
                <a href="#" onclick="app.navigate('register')" class="btn-register">Đăng ký</a>
            `;
            document.querySelectorAll('.admin-only').forEach(el => {
                el.style.display = 'none';
            });
        }
    }

    isLoggedIn() { return !!this.currentUser; }
    isAdmin() { return this.currentUser && this.currentUser.role === 'admin'; }
    getCurrentUser() { return this.currentUser; }
    getFingerprint() { return this.fingerprint; }
}

// ============================================
// MAIN APPLICATION
// ============================================
class App {
    constructor() {
        this.db = new Database();
        this.auth = new Auth(this.db);
        this.currentPage = 1;
        this.currentFilter = { category: 'all', sort: 'newest', search: '', priceRange: 'all' };
        this.viewedDocuments = new Set();
        this.wishlist = new Set();
        this.cart = [];
        this.voucherApplied = null;
        this.readingProgress = {};
        this.notifications = [];
        this.documentCache = new Map();
        this.init();
    }

    async init() {
        await this.db.init();
        await this.seedData();
        await this.loadWishlist();
        await this.loadCart();
        await this.loadReadingProgress();
        await this.loadNotifications();
        this.setupProtection();
        this.setupEvents();
        this.setupPWA();
        this.navigate(window.location.hash.replace('#', '') || 'home');
        this.startAutoBackup();
        this.showToast('🛡️ DocSecure đã sẵn sàng', 'success');
    }

    // ============================================
    // SEED DATA
    // ============================================
    async seedData() {
        const users = await this.db.getAll('users');
        if (users.length === 0) {
            // Admin
            await this.db.add('users', {
                id: this.db.generateId(),
                username: 'admin',
                email: CONFIG.adminEmail,
                password: Utils.hash(CONFIG.adminPassword),
                fullName: 'Quản trị viên',
                role: 'admin',
                status: 'active',
                avatar: null,
                boundFingerprint: null,
                boundDate: null,
                createdAt: new Date().toISOString(),
                permissions: ['*'],
                stats: { totalPurchases: 0, totalSpent: 0, documentsViewed: 0 },
                preferences: { theme: 'light', notifications: true, autoSave: true }
            });

            // Categories
            const categories = [
                { id: 'programming', name: 'Lập trình', icon: 'fa-code' },
                { id: 'design', name: 'Thiết kế', icon: 'fa-paint-brush' },
                { id: 'data', name: 'Dữ liệu', icon: 'fa-chart-bar' },
                { id: 'business', name: 'Kinh doanh', icon: 'fa-briefcase' },
                { id: 'language', name: 'Ngôn ngữ', icon: 'fa-language' },
                { id: 'marketing', name: 'Marketing', icon: 'fa-bullhorn' },
                { id: 'finance', name: 'Tài chính', icon: 'fa-coins' },
                { id: 'health', name: 'Sức khỏe', icon: 'fa-heartbeat' }
            ];
            for (const cat of categories) {
                await this.db.add('categories', cat);
            }

            // Payment settings
            await this.db.add('paymentSettings', {
                id: 'default',
                bankName: 'Techcombank',
                accountNumber: '1234567890',
                accountHolder: 'DocSecure Company',
                transferContent: 'Thanh toan tai lieu',
                qrCode: Utils.generateQR('Techcombank|1234567890|DocSecure Company|Thanh toan tai lieu')
            });

            // Sample documents
            const sampleDocs = [
                { 
                    title: 'Giáo trình JavaScript Nâng Cao', 
                    category: 'programming', 
                    price: 0, 
                    author: 'Nguyễn Văn A',
                    description: 'Tài liệu đầy đủ về JavaScript từ cơ bản đến nâng cao, bao gồm ES6+, async/await, và các pattern phổ biến.',
                    content: 'Nội dung chi tiết về JavaScript Nâng Cao...'
                },
                { 
                    title: 'Thiết kế UI/UX Chuyên Nghiệp', 
                    category: 'design', 
                    price: 199000, 
                    author: 'Trần Thị B',
                    description: 'Hướng dẫn toàn diện về thiết kế giao diện và trải nghiệm người dùng, áp dụng cho web và mobile.',
                    content: 'Nội dung về Thiết kế UI/UX...'
                },
                { 
                    title: 'Phân tích Dữ liệu với Python', 
                    category: 'data', 
                    price: 299000, 
                    author: 'Lê Văn C',
                    description: 'Khóa học phân tích dữ liệu sử dụng Python, pandas, numpy, và matplotlib.',
                    content: 'Nội dung về Phân tích Dữ liệu...'
                },
                { 
                    title: 'Chiến lược Marketing Digital', 
                    category: 'marketing', 
                    price: 249000, 
                    author: 'Phạm Thị D',
                    description: 'Chiến lược marketing digital toàn diện từ A-Z cho doanh nghiệp.',
                    content: 'Nội dung về Marketing Digital...'
                }
            ];
            for (const doc of sampleDocs) {
                await this.db.add('documents', {
                    id: this.db.generateId(),
                    ...doc,
                    ownerId: 'admin',
                    uploadDate: new Date().toISOString(),
                    views: Math.floor(Math.random() * 200) + 10,
                    downloads: Math.floor(Math.random() * 50) + 5,
                    rating: (Math.random() * 2 + 3).toFixed(1),
                    status: 'published'
                });
            }

            // Sample vouchers
            await this.db.add('vouchers', {
                id: this.db.generateId(),
                code: 'WELCOME20',
                discount: 20,
                type: 'percentage',
                expires: new Date(Date.now() + 30*24*60*60*1000).toISOString(),
                used: false,
                maxUses: 100,
                usedCount: 0,
                userId: null,
                createdAt: new Date().toISOString()
            });
        }
    }

    // ============================================
    // PROTECTION SYSTEM
    // ============================================
    setupProtection() {
        // Prevent context menu
        document.addEventListener('contextmenu', (e) => {
            if (this.auth.isLoggedIn() && document.querySelector('.document-viewer.active')) {
                e.preventDefault();
                this.showToast('Chức năng này đã bị vô hiệu hóa', 'warning');
            }
        });

        // Prevent copy
        document.addEventListener('copy', (e) => {
            if (document.querySelector('.document-viewer.active')) {
                e.preventDefault();
                this.showToast('Sao chép nội dung không được phép', 'warning');
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'p')) {
                if (document.querySelector('.document-viewer.active')) {
                    e.preventDefault();
                    this.showToast('Chức năng này đã bị vô hiệu hóa', 'warning');
                }
            }
            if (e.key === 'PrintScreen' && document.querySelector('.document-viewer.active')) {
                this.handleScreenCapture();
                this.showToast('⚠️ Phát hiện chụp màn hình!', 'error');
            }
        });

        // Detect DevTools
        let devtoolsOpen = false;
        const checkDevtools = () => {
            const widthDiff = window.outerWidth - window.innerWidth;
            const heightDiff = window.outerHeight - window.innerHeight;
            if ((widthDiff > 160 || heightDiff > 160) && !devtoolsOpen) {
                devtoolsOpen = true;
                if (document.querySelector('.document-viewer.active')) {
                    document.getElementById('documentContent').style.filter = 'blur(4px)';
                }
                this.showToast('⚠️ Phát hiện DevTools! Nội dung đã được bảo vệ.', 'warning');
            } else if (widthDiff <= 160 && heightDiff <= 160 && devtoolsOpen) {
                devtoolsOpen = false;
                if (document.querySelector('.document-viewer.active')) {
                    document.getElementById('documentContent').style.filter = 'none';
                }
            }
        };
        setInterval(checkDevtools, 1500);
    }

    handleScreenCapture() {
        const viewer = document.getElementById('documentViewer');
        if (viewer && viewer.classList.contains('active')) {
            const content = document.getElementById('documentContent');
            if (content) {
                content.style.filter = 'blur(12px)';
                content.style.transition = 'filter 0.1s';
                setTimeout(() => {
                    content.style.filter = 'none';
                }, 800);
            }
        }
    }

    // ============================================
    // WATERMARK
    // ============================================
    renderWatermark(container, user) {
        if (!user) return;
        const overlay = document.getElementById('watermarkOverlay');
        if (!overlay) return;

        const watermarkText = Utils.generateWatermark(user.username, user.email, user.id);
        overlay.innerHTML = '';
        
        const containerWidth = container?.offsetWidth || window.innerWidth;
        const containerHeight = container?.offsetHeight || window.innerHeight;
        const spacing = CONFIG.watermarkSpacing;
        const cols = Math.ceil(containerWidth / spacing) + 2;
        const rows = Math.ceil(containerHeight / spacing) + 2;

        const fragments = [];
        for (let i = 0; i < rows; i++) {
            for (let j = 0; j < cols; j++) {
                const offsetX = (i % 2 === 0) ? 0 : spacing / 2;
                const left = (j * spacing + offsetX) % (containerWidth + spacing) - spacing/2;
                const top = i * spacing - spacing/2;
                fragments.push(`
                    <span class="watermark-text" 
                          style="left:${left}px;top:${top}px;opacity:${CONFIG.watermarkOpacity};font-size:1.4rem;">
                        ${watermarkText}
                    </span>
                `);
            }
        }
        overlay.innerHTML = fragments.join('');

        // Animate watermark positions
        let angle = 0;
        setInterval(() => {
            angle = (angle + 0.5) % 360;
            overlay.style.transform = `rotate(${angle * 0.01}deg)`;
        }, 5000);
    }

    // ============================================
    // TOKEN SYSTEM
    // ============================================
    async generateAccessToken(documentId) {
        if (!this.auth.isLoggedIn()) {
            throw new Error('Vui lòng đăng nhập');
        }

        const token = {
            id: Utils.generateToken(),
            userId: this.auth.currentUser.id,
            documentId: documentId,
            expires: Date.now() + CONFIG.tokenExpiry,
            created: new Date().toISOString()
        };

        await this.db.add('tokens', token);

        // Cleanup expired tokens
        const allTokens = await this.db.getAll('tokens');
        const now = Date.now();
        for (const t of allTokens) {
            if (t.expires < now) {
                await this.db.delete('tokens', t.id);
            }
        }

        return token.id;
    }

    async validateToken(tokenId) {
        const token = await this.db.get('tokens', tokenId);
        if (!token) return null;
        if (token.expires < Date.now()) {
            await this.db.delete('tokens', tokenId);
            return null;
        }
        return token;
    }

    // ============================================
    // DOCUMENT ACCESS
    // ============================================
    async checkDocumentAccess(documentId) {
        if (!this.auth.isLoggedIn()) return false;
        
        const doc = await this.db.get('documents', documentId);
        if (!doc) return false;

        if (this.auth.isAdmin() || doc.ownerId === this.auth.currentUser.id) {
            return true;
        }

        const user = await this.db.get('users', this.auth.currentUser.id);
        if (user.permissions && user.permissions.includes(documentId)) {
            return true;
        }

        const purchases = await this.db.query('purchases', 'userId', this.auth.currentUser.id);
        return purchases.some(p => p.documentId === documentId && p.status === 'completed');
    }

    // ============================================
    // WISHLIST
    // ============================================
    async loadWishlist() {
        if (!this.auth.isLoggedIn()) return;
        const items = await this.db.query('wishlist', 'userId', this.auth.currentUser.id);
        this.wishlist = new Set(items.map(i => i.documentId));
        this.updateWishlistUI();
    }

    async toggleWishlist(documentId) {
        if (!this.auth.isLoggedIn()) {
            this.showToast('Vui lòng đăng nhập để thêm vào yêu thích', 'warning');
            this.navigate('login');
            return;
        }

        if (this.wishlist.has(documentId)) {
            await this.db.delete('wishlist', documentId + '_' + this.auth.currentUser.id);
            this.wishlist.delete(documentId);
            this.showToast('Đã xóa khỏi danh sách yêu thích', 'info');
        } else {
            await this.db.add('wishlist', {
                id: documentId + '_' + this.auth.currentUser.id,
                userId: this.auth.currentUser.id,
                documentId: documentId,
                createdAt: new Date().toISOString()
            });
            this.wishlist.add(documentId);
            this.showToast('Đã thêm vào danh sách yêu thích', 'success');
        }
        this.updateWishlistUI();
    }

    updateWishlistUI() {
        document.querySelectorAll('.wishlist-btn').forEach(btn => {
            const docId = btn.dataset.documentId;
            if (this.wishlist.has(docId)) {
                btn.classList.add('active');
                btn.innerHTML = '<i class="fas fa-heart"></i>';
            } else {
                btn.classList.remove('active');
                btn.innerHTML = '<i class="far fa-heart"></i>';
            }
        });
    }

    // ============================================
    // CART & VOUCHER
    // ============================================
    async loadCart() {
        const saved = localStorage.getItem(CONFIG.storagePrefix + 'cart');
        if (saved) {
            try {
                this.cart = JSON.parse(saved);
                this.updateCartUI();
            } catch (e) {
                this.cart = [];
            }
        }
    }

    addToCart(documentId) {
        if (!this.cart.includes(documentId)) {
            this.cart.push(documentId);
            localStorage.setItem(CONFIG.storagePrefix + 'cart', JSON.stringify(this.cart));
            this.updateCartUI();
            this.showToast('Đã thêm vào giỏ hàng', 'success');
        } else {
            this.showToast('Tài liệu đã có trong giỏ hàng', 'info');
        }
    }

    removeFromCart(documentId) {
        this.cart = this.cart.filter(id => id !== documentId);
        localStorage.setItem(CONFIG.storagePrefix + 'cart', JSON.stringify(this.cart));
        this.updateCartUI();
        this.showToast('Đã xóa khỏi giỏ hàng', 'info');
        if (this.cart.length === 0) {
            this.navigate('home');
        } else {
            this.renderCart();
        }
    }

    updateCartUI() {
        const badge = document.getElementById('cartBadge');
        if (badge) {
            badge.textContent = this.cart.length;
            badge.style.display = this.cart.length > 0 ? 'inline' : 'none';
        }
    }

    applyVoucher(code) {
        return new Promise(async (resolve, reject) => {
            const vouchers = await this.db.query('vouchers', 'code', code);
            const voucher = vouchers[0];
            
            if (!voucher) {
                reject(new Error('Mã giảm giá không hợp lệ'));
                return;
            }
            
            if (voucher.used || (voucher.maxUses && voucher.usedCount >= voucher.maxUses)) {
                reject(new Error('Mã giảm giá đã được sử dụng hết'));
                return;
            }
            
            if (voucher.expires && new Date(voucher.expires) < new Date()) {
                reject(new Error('Mã giảm giá đã hết hạn'));
                return;
            }
            
            this.voucherApplied = voucher;
            resolve(voucher);
        });
    }

    // ============================================
    // READING PROGRESS
    // ============================================
    async loadReadingProgress() {
        if (!this.auth.isLoggedIn()) return;
        const progress = await this.db.query('readingProgress', 'userId', this.auth.currentUser.id);
        progress.forEach(p => {
            this.readingProgress[p.documentId] = p.progress;
        });
    }

    async saveReadingProgress(documentId, progress) {
        if (!this.auth.isLoggedIn()) return;
        
        const id = documentId + '_' + this.auth.currentUser.id;
        const existing = await this.db.get('readingProgress', id);
        
        if (existing) {
            existing.progress = progress;
            existing.updatedAt = new Date().toISOString();
            await this.db.update('readingProgress', existing);
        } else {
            await this.db.add('readingProgress', {
                id: id,
                userId: this.auth.currentUser.id,
                documentId: documentId,
                progress: progress,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            });
        }
        this.readingProgress[documentId] = progress;
    }

    // ============================================
    // NOTIFICATIONS
    // ============================================
    async loadNotifications() {
        if (!this.auth.isLoggedIn()) return;
        const notifs = await this.db.query('notifications', 'userId', this.auth.currentUser.id);
        this.notifications = notifs.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        this.updateNotificationUI();
    }

    async addNotification(userId, title, body, url = null) {
        const notif = {
            id: this.db.generateId(),
            userId: userId,
            title: title,
            body: body,
            url: url,
            read: false,
            createdAt: new Date().toISOString()
        };
        await this.db.add('notifications', notif);
        
        // Push notification if supported
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, { body: body, icon: '/assets/icons/icon-192.png' });
        }
        
        this.loadNotifications();
    }

    toggleNotifications() {
        const dropdown = document.getElementById('notifDropdown');
        dropdown.classList.toggle('show');
        if (dropdown.classList.contains('show')) {
            this.renderNotifications();
        }
    }

    renderNotifications() {
        const list = document.getElementById('notifList');
        if (!list) return;
        
        if (this.notifications.length === 0) {
            list.innerHTML = '<div class="notif-empty">Không có thông báo nào</div>';
            return;
        }
        
        list.innerHTML = this.notifications.slice(0, 20).map(n => `
            <div class="notif-item ${n.read ? 'read' : 'unread'}" onclick="app.markNotificationRead('${n.id}')">
                <div class="notif-title">${n.title}</div>
                <div class="notif-body">${n.body}</div>
                <div class="notif-time">${Utils.formatDate(n.createdAt)}</div>
            </div>
        `).join('');
    }

    async markNotificationRead(id) {
        const notif = await this.db.get('notifications', id);
        if (notif) {
            notif.read = true;
            await this.db.update('notifications', notif);
            this.loadNotifications();
        }
    }

    async clearNotifications() {
        const unread = this.notifications.filter(n => !n.read);
        for (const n of unread) {
            n.read = true;
            await this.db.update('notifications', n);
        }
        this.loadNotifications();
        this.showToast('Đã đánh dấu tất cả thông báo là đã đọc', 'success');
    }

    updateNotificationUI() {
        const badge = document.getElementById('notifBadge');
        if (badge) {
            const unread = this.notifications.filter(n => !n.read);
            badge.textContent = unread.length;
            badge.style.display = unread.length > 0 ? 'inline' : 'none';
        }
    }

    // ============================================
    // BACKUP & RESTORE
    // ============================================
    async createBackup() {
        this.showToast('Đang tạo bản sao lưu...', 'info');
        
        try {
            const data = {};
            const stores = ['users', 'documents', 'purchases', 'views', 'categories', 'vouchers', 'orders', 'paymentSettings'];
            
            for (const store of stores) {
                data[store] = await this.db.getAll(store);
            }
            
            const backup = {
                id: this.db.generateId(),
                version: CONFIG.version,
                timestamp: new Date().toISOString(),
                data: data,
                size: JSON.stringify(data).length
            };
            
            await this.db.add('backups', backup);
            
            // Download backup file
            const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `docsecure_backup_${new Date().toISOString().slice(0,10)}.json`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            
            this.showToast('Sao lưu thành công!', 'success');
        } catch (error) {
            this.showToast('Lỗi khi sao lưu: ' + error.message, 'error');
        }
    }

    async restoreBackup(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    const backup = JSON.parse(e.target.result);
                    
                    if (!backup.version || !backup.data) {
                        reject(new Error('File backup không hợp lệ'));
                        return;
                    }
                    
                    // Clear existing data
                    const stores = ['users', 'documents', 'purchases', 'views', 'categories', 'vouchers', 'orders'];
                    for (const store of stores) {
                        await this.db.clear(store);
                    }
                    
                    // Restore data
                    for (const [store, items] of Object.entries(backup.data)) {
                        for (const item of items) {
                            await this.db.add(store, item);
                        }
                    }
                    
                    resolve(backup);
                } catch (error) {
                    reject(new Error('Lỗi khi đọc file backup: ' + error.message));
                }
            };
            reader.readAsText(file);
        });
    }

    startAutoBackup() {
        // Auto backup every 24 hours
        setInterval(() => {
            if (this.auth.isAdmin()) {
                this.createBackup();
            }
        }, 24 * 60 * 60 * 1000);
    }

    // ============================================
    // NAVIGATION
    // ============================================
    navigate(page, data = null) {
        window.location.hash = page;
        this.currentPage = 1;
        this.render(page, data);
    }

    render(page, data = null) {
        const main = document.getElementById('mainContent');
        if (!main) return;

        switch(page) {
            case 'home': this.renderHome(main); break;
            case 'documents': this.renderDocuments(main); break;
            case 'document': if (data) this.renderDocumentDetail(main, data); break;
            case 'login': this.renderLogin(main); break;
            case 'register': this.renderRegister(main); break;
            case 'profile': this.renderProfile(main); break;
            case 'purchases': this.renderPurchases(main); break;
            case 'wishlist': this.renderWishlist(main); break;
            case 'view-history': this.renderViewHistory(main); break;
            case 'cart': this.renderCart(main); break;
            default: this.renderHome(main);
        }
    }

    // ============================================
    // RENDER: HOME
    // ============================================
    renderHome(container) {
        container.innerHTML = `
            <section class="hero">
                <div class="container">
                    <div class="hero-content">
                        <h1>Bảo vệ tài liệu của bạn với <span>DocSecure</span></h1>
                        <p>Hệ thống quản lý và phân phối tài liệu an toàn với công nghệ bảo mật hàng đầu</p>
                        <div class="hero-actions">
                            <a href="#" onclick="app.navigate('documents')" class="btn btn-primary">
                                <i class="fas fa-search"></i> Khám phá ngay
                            </a>
                            ${!this.auth.isLoggedIn() ? `
                                <a href="#" onclick="app.navigate('register')" class="btn btn-outline">
                                    <i class="fas fa-user-plus"></i> Đăng ký
                                </a>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </section>
            <section class="documents-section">
                <div class="container">
                    <div class="section-header">
                        <h2><i class="fas fa-star" style="color:var(--warning)"></i> Tài liệu nổi bật</h2>
                        <a href="#" onclick="app.navigate('documents')" class="btn btn-outline btn-sm">Xem tất cả →</a>
                    </div>
                    <div class="document-grid" id="featuredGrid"></div>
                </div>
            </section>
        `;
        this.renderFeaturedDocuments();
    }

    async renderFeaturedDocuments() {
        const grid = document.getElementById('featuredGrid');
        if (!grid) return;

        const docs = await this.db.getAll('documents');
        const featured = docs
            .filter(d => d.status === 'published')
            .sort((a, b) => (b.views || 0) - (a.views || 0))
            .slice(0, 6);
        grid.innerHTML = this.renderDocumentCards(featured);
    }

    // ============================================
    // RENDER: DOCUMENTS
    // ============================================
    async renderDocuments(container, searchQuery = '') {
        const categories = await this.db.getAll('categories');
        
        container.innerHTML = `
            <section class="documents-section">
                <div class="container">
                    <div class="section-header">
                        <h2><i class="fas fa-file-alt"></i> Thư viện tài liệu</h2>
                        <div class="filters">
                            <select id="categoryFilter" onchange="app.filterDocuments()">
                                <option value="all">Tất cả danh mục</option>
                                ${categories.map(c => `<option value="${c.id}">${c.name}</option>`).join('')}
                            </select>
                            <select id="sortFilter" onchange="app.filterDocuments()">
                                <option value="newest">Mới nhất</option>
                                <option value="popular">Phổ biến</option>
                                <option value="price-low">Giá thấp → cao</option>
                                <option value="price-high">Giá cao → thấp</option>
                            </select>
                            <select id="priceFilter" onchange="app.filterDocuments()">
                                <option value="all">Tất cả giá</option>
                                <option value="free">Miễn phí</option>
                                <option value="paid">Có phí</option>
                            </select>
                        </div>
                    </div>
                    <div class="document-grid" id="documentGrid"></div>
                    <div class="load-more">
                        <button class="btn btn-outline" id="loadMoreBtn" onclick="app.loadMore()">
                            <i class="fas fa-chevron-down"></i> Tải thêm
                        </button>
                    </div>
                </div>
            </section>
        `;

        this.currentFilter.search = searchQuery || '';
        await this.loadDocuments();
    }

    async loadDocuments() {
        const grid = document.getElementById('documentGrid');
        if (!grid) return;

        let docs = await this.db.getAll('documents');
        docs = docs.filter(d => d.status === 'published');
        
        // Search filter
        if (this.currentFilter.search) {
            const q = this.currentFilter.search.toLowerCase();
            docs = docs.filter(d => 
                d.title.toLowerCase().includes(q) || 
                (d.author && d.author.toLowerCase().includes(q)) ||
                (d.description && d.description.toLowerCase().includes(q))
            );
        }

        // Category filter
        const category = document.getElementById('categoryFilter')?.value || 'all';
        if (category !== 'all') {
            docs = docs.filter(d => d.category === category);
        }

        // Price filter
        const priceFilter = document.getElementById('priceFilter')?.value || 'all';
        if (priceFilter === 'free') {
            docs = docs.filter(d => !d.price || d.price === 0);
        } else if (priceFilter === 'paid') {
            docs = docs.filter(d => d.price && d.price > 0);
        }

        // Sort
        const sort = document.getElementById('sortFilter')?.value || 'newest';
        docs.sort((a, b) => {
            switch(sort) {
                case 'newest': return new Date(b.uploadDate) - new Date(a.uploadDate);
                case 'popular': return (b.views || 0) - (a.views || 0);
                case 'price-low': return (a.price || 0) - (b.price || 0);
                case 'price-high': return (b.price || 0) - (a.price || 0);
                default: return 0;
            }
        });

        // Paginate
        const start = 0;
        const end = this.currentPage * CONFIG.pageSize;
        const pageDocs = docs.slice(start, end);

        if (pageDocs.length === 0 && this.currentPage > 1) {
            this.currentPage--;
            this.showToast('Đã tải hết tài liệu', 'info');
            return;
        }

        grid.innerHTML = this.renderDocumentCards(pageDocs);

        const loadMoreBtn = document.getElementById('loadMoreBtn');
        if (loadMoreBtn) {
            loadMoreBtn.style.display = end >= docs.length ? 'none' : 'inline-flex';
        }
    }

    renderDocumentCards(docs) {
        if (!docs || docs.length === 0) {
            return `<div class="text-center" style="grid-column:1/-1;padding:3rem 0;color:var(--gray-500);">
                <i class="fas fa-inbox" style="font-size:3rem;display:block;margin-bottom:1rem;"></i>
                <p>Không tìm thấy tài liệu nào</p>
            </div>`;
        }

        return docs.map(doc => {
            const isFree = !doc.price || doc.price === 0;
            const inWishlist = this.wishlist.has(doc.id);
            
            return `
                <div class="document-card">
                    <div class="document-thumb">
                        <i class="fas fa-file-pdf doc-icon"></i>
                        <span class="document-badge ${isFree ? 'free' : 'premium'}">
                            ${isFree ? 'Miễn phí' : 'Premium'}
                        </span>
                    </div>
                    <div class="document-body">
                        <h3><a href="#" onclick="app.viewDocument('${doc.id}')">${Utils.escapeHtml(doc.title)}</a></h3>
                        <div class="document-meta">
                            <span><i class="fas fa-user"></i> ${Utils.escapeHtml(doc.author || 'Unknown')}</span>
                            <span><i class="fas fa-eye"></i> ${doc.views || 0}</span>
                            <span><i class="fas fa-download"></i> ${doc.downloads || 0}</span>
                        </div>
                        <div class="document-footer">
                            <span class="document-price ${isFree ? 'free' : ''}">
                                ${isFree ? 'Miễn phí' : doc.price.toLocaleString() + 'đ'}
                            </span>
                            <div class="document-actions">
                                <button class="btn btn-sm btn-outline wishlist-btn ${inWishlist ? 'active' : ''}" 
                                        data-document-id="${doc.id}" 
                                        onclick="app.toggleWishlist('${doc.id}')">
                                    <i class="${inWishlist ? 'fas' : 'far'} fa-heart"></i>
                                </button>
                                <button class="btn btn-sm btn-outline" onclick="app.viewDocument('${doc.id}')">
                                    <i class="fas fa-eye"></i>
                                </button>
                                ${isFree ? `
                                    <button class="btn btn-sm btn-success" onclick="app.downloadDocument('${doc.id}')">
                                        <i class="fas fa-download"></i>
                                    </button>
                                ` : `
                                    <button class="btn btn-sm btn-primary" onclick="app.addToCart('${doc.id}')">
                                        <i class="fas fa-shopping-cart"></i>
                                    </button>
                                `}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    filterDocuments() {
        this.currentPage = 1;
        this.loadDocuments();
    }

    loadMore() {
        this.currentPage++;
        this.loadDocuments();
    }

    // ============================================
    // RENDER: DOCUMENT DETAIL
    // ============================================
    async viewDocument(id) {
        const doc = await this.db.get('documents', id);
        if (!doc) {
            this.showToast('Không tìm thấy tài liệu', 'error');
            return;
        }

        // Check access
        const hasAccess = await this.checkDocumentAccess(id);
        if (!hasAccess && doc.price && doc.price > 0) {
            this.showToast('Vui lòng mua tài liệu để xem nội dung', 'warning');
            const confirm = window.confirm(`Tài liệu "${doc.title}" có giá ${doc.price.toLocaleString()}đ. Bạn muốn mua?`);
            if (confirm) {
                this.addToCart(id);
                this.navigate('cart');
            }
            return;
        }

        // Record view
        if (this.auth.isLoggedIn()) {
            await this.db.add('views', {
                id: this.db.generateId(),
                userId: this.auth.currentUser.id,
                documentId: doc.id,
                viewDate: new Date().toISOString(),
                fingerprint: Utils.getFingerprint()
            });
            
            const user = await this.db.get('users', this.auth.currentUser.id);
            if (user) {
                user.stats.documentsViewed = (user.stats.documentsViewed || 0) + 1;
                await this.db.update('users', user);
            }
        }

        // Update views
        doc.views = (doc.views || 0) + 1;
        await this.db.update('documents', doc);

        this.showDocumentViewer(doc);
    }

    showDocumentViewer(doc) {
        const viewer = document.getElementById('documentViewer');
        const body = document.getElementById('viewerBody');
        const content = document.getElementById('documentContent');
        const overlay = document.getElementById('watermarkOverlay');

        overlay.innerHTML = '';

        // Get reading progress
        const progress = this.readingProgress[doc.id] || 0;
        document.getElementById('progressBar').style.width = progress + '%';

        const protectionBadge = Utils.supportsScreenProtection() ? 
            '<span class="protection-badge"><i class="fas fa-shield-alt"></i> Được bảo vệ chống chụp màn hình</span>' : '';

        content.innerHTML = `
            ${protectionBadge}
            <div class="doc-text">
                ${doc.content || 'Nội dung tài liệu đang được cập nhật...'}
                <div style="margin-top:2rem;font-size:0.85rem;color:var(--gray-500);border-top:1px solid var(--gray-300);padding-top:1rem;display:flex;justify-content:space-between;flex-wrap:wrap;">
                    <span><i class="fas fa-lock"></i> Bảo vệ bởi DocSecure</span>
                    <span>Tiến độ đọc: ${Math.round(progress)}%</span>
                </div>
            </div>
        `;

        if (this.auth.isLoggedIn()) {
            this.renderWatermark(body, this.auth.currentUser);
        }

        viewer.classList.add('active');
        document.body.style.overflow = 'hidden';

        // Track reading progress
        const trackProgress = Utils.throttle(() => {
            const scrollTop = body.scrollTop || body.scrollY || 0;
            const scrollHeight = body.scrollHeight - body.clientHeight;
            if (scrollHeight > 0) {
                const pct = Math.round((scrollTop / scrollHeight) * 100);
                this.saveReadingProgress(doc.id, pct);
                document.getElementById('progressBar').style.width = pct + '%';
            }
        }, 1000);

        body.addEventListener('scroll', trackProgress);

        // Setup protection for viewer
        this.enableViewerProtection();
    }

    enableViewerProtection() {
        const viewer = document.getElementById('documentViewer');
        if (viewer) {
            viewer.style.userSelect = 'none';
            viewer.style.webkitUserSelect = 'none';
        }
    }

    closeDocument() {
        const viewer = document.getElementById('documentViewer');
        viewer.classList.remove('active');
        document.body.style.overflow = '';
        document.getElementById('documentContent').innerHTML = '';
        document.getElementById('watermarkOverlay').innerHTML = '';
        document.getElementById('progressBar').style.width = '0%';
    }

    // ============================================
    // RENDER: CART
    // ============================================
    async renderCart() {
        const container = document.getElementById('mainContent');
        if (this.cart.length === 0) {
            container.innerHTML = `
                <section class="documents-section">
                    <div class="container text-center" style="padding:4rem 0;">
                        <i class="fas fa-shopping-cart" style="font-size:4rem;color:var(--gray-300);display:block;margin-bottom:1rem;"></i>
                        <h3>Giỏ hàng trống</h3>
                        <p style="color:var(--gray-500);">Hãy thêm tài liệu vào giỏ hàng để mua</p>
                        <a href="#" onclick="app.navigate('documents')" class="btn btn-primary" style="margin-top:1rem;">
                            <i class="fas fa-search"></i> Khám phá
                        </a>
                    </div>
                </section>
            `;
            return;
        }

        const cartDocs = [];
        let total = 0;
        for (const id of this.cart) {
            const doc = await this.db.get('documents', id);
            if (doc) {
                cartDocs.push(doc);
                total += doc.price || 0;
            }
        }

        const discount = this.voucherApplied ? 
            this.voucherApplied.type === 'percentage' ? total * this.voucherApplied.discount / 100 : this.voucherApplied.discount 
            : 0;
        const finalTotal = Math.max(0, total - discount);

        container.innerHTML = `
            <section class="documents-section">
                <div class="container">
                    <div class="section-header">
                        <h2><i class="fas fa-shopping-cart"></i> Giỏ hàng</h2>
                        <span>${this.cart.length} tài liệu</span>
                    </div>
                    
                    <div style="background:var(--white);border-radius:var(--radius);padding:1.5rem;box-shadow:var(--shadow);">
                        ${cartDocs.map(doc => `
                            <div style="display:flex;justify-content:space-between;align-items:center;padding:0.75rem 0;border-bottom:1px solid var(--gray-100);">
                                <div>
                                    <h4>${Utils.escapeHtml(doc.title)}</h4>
                                    <p style="color:var(--gray-500);font-size:0.9rem;">${Utils.escapeHtml(doc.author || 'Unknown')}</p>
                                </div>
                                <div style="display:flex;align-items:center;gap:1rem;">
                                    <span style="font-weight:700;color:var(--primary);">${(doc.price || 0).toLocaleString()}đ</span>
                                    <button class="btn btn-sm btn-danger" onclick="app.removeFromCart('${doc.id}')">
                                        <i class="fas fa-times"></i>
                                    </button>
                                </div>
                            </div>
                        `).join('')}
                        
                        <div style="margin-top:1.5rem;padding-top:1.5rem;border-top:2px solid var(--gray-200);">
                            <div style="display:flex;gap:1rem;margin-bottom:1rem;flex-wrap:wrap;">
                                <input type="text" id="voucherInput" placeholder="Nhập mã giảm giá" style="flex:1;min-width:200px;padding:0.5rem 1rem;border:2px solid var(--gray-200);border-radius:var(--radius-sm);">
                                <button class="btn btn-outline" onclick="app.applyVoucherUI()">Áp dụng</button>
                            </div>
                            
                            <div style="display:flex;justify-content:space-between;font-size:1.1rem;flex-wrap:wrap;gap:0.5rem;">
                                <span>Tạm tính: <strong>${total.toLocaleString()}đ</strong></span>
                                ${discount > 0 ? `<span style="color:var(--success);">Giảm giá: -${discount.toLocaleString()}đ</span>` : ''}
                                <span style="font-size:1.3rem;font-weight:700;color:var(--primary);">
                                    Tổng cộng: ${finalTotal.toLocaleString()}đ
                                </span>
                            </div>
                            
                            <button class="btn btn-primary btn-block" style="margin-top:1rem;" onclick="app.checkout()">
                                <i class="fas fa-credit-card"></i> Thanh toán
                            </button>
                        </div>
                    </div>
                </div>
            </section>
        `;
    }

    async applyVoucherUI() {
        const input = document.getElementById('voucherInput');
        const code = input.value.trim().toUpperCase();
        
        if (!code) {
            this.showToast('Vui lòng nhập mã giảm giá', 'warning');
            return;
        }

        try {
            const voucher = await this.applyVoucher(code);
            this.showToast(`Áp dụng mã giảm giá ${voucher.discount}% thành công!`, 'success');
            this.renderCart();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    // ============================================
    // RENDER: WISHLIST
    // ============================================
    async renderWishlist() {
        const container = document.getElementById('mainContent');
        
        if (this.wishlist.size === 0) {
            container.innerHTML = `
                <section class="documents-section">
                    <div class="container text-center" style="padding:4rem 0;">
                        <i class="far fa-heart" style="font-size:4rem;color:var(--gray-300);display:block;margin-bottom:1rem;"></i>
                        <h3>Danh sách yêu thích trống</h3>
                        <p style="color:var(--gray-500);">Thêm tài liệu vào yêu thích để xem sau</p>
                        <a href="#" onclick="app.navigate('documents')" class="btn btn-primary" style="margin-top:1rem;">
                            <i class="fas fa-search"></i> Khám phá
                        </a>
                    </div>
                </section>
            `;
            return;
        }

        const docs = [];
        for (const id of this.wishlist) {
            const doc = await this.db.get('documents', id);
            if (doc) docs.push(doc);
        }

        container.innerHTML = `
            <section class="documents-section">
                <div class="container">
                    <div class="section-header">
                        <h2><i class="fas fa-heart" style="color:var(--danger)"></i> Yêu thích (${docs.length})</h2>
                    </div>
                    <div class="document-grid">
                        ${this.renderDocumentCards(docs)}
                    </div>
                </div>
            </section>
        `;
    }

    // ============================================
    // CHECKOUT
    // ============================================
    async checkout() {
        if (!this.auth.isLoggedIn()) {
            this.showToast('Vui lòng đăng nhập để thanh toán', 'error');
            this.navigate('login');
            return;
        }

        if (this.cart.length === 0) {
            this.showToast('Giỏ hàng trống', 'error');
            return;
        }

        // Show payment modal
        const modal = document.getElementById('modal');
        const body = document.getElementById('modalBody');

        const paymentSettings = await this.db.get('paymentSettings', 'default');
        
        body.innerHTML = `
            <h2><i class="fas fa-credit-card"></i> Thanh toán</h2>
            <p style="color:var(--gray-500);margin-bottom:1rem;">Vui lòng chuyển khoản theo thông tin bên dưới</p>
            
            <div style="background:var(--gray-50);padding:1.5rem;border-radius:var(--radius);margin-bottom:1rem;">
                <div style="display:flex;flex-direction:column;align-items:center;gap:0.5rem;">
                    <img src="${paymentSettings?.qrCode || Utils.generateQR('Bank Transfer')}" alt="QR Code" style="width:200px;height:200px;">
                    <div style="text-align:center;">
                        <p><strong>Ngân hàng:</strong> ${paymentSettings?.bankName || 'Techcombank'}</p>
                        <p><strong>Số tài khoản:</strong> ${paymentSettings?.accountNumber || '1234567890'}</p>
                        <p><strong>Chủ tài khoản:</strong> ${paymentSettings?.accountHolder || 'DocSecure Company'}</p>
                        <p><strong>Nội dung:</strong> ${paymentSettings?.transferContent || 'Thanh toan tai lieu'} - ${this.auth.currentUser.username}</p>
                        <p style="font-size:1.2rem;font-weight:700;color:var(--primary);margin-top:0.5rem;">
                            Số tiền: ${this.cart.reduce((sum, id) => sum + (this.getDocPrice(id) || 0), 0).toLocaleString()}đ
                        </p>
                    </div>
                </div>
            </div>
            
            <div style="display:flex;gap:1rem;flex-wrap:wrap;">
                <button class="btn btn-success" onclick="app.confirmPayment()" style="flex:1;">
                    <i class="fas fa-check"></i> Xác nhận thanh toán
                </button>
                <button class="btn btn-outline" onclick="app.closeModal()">Hủy</button>
            </div>
        `;

        modal.classList.add('active');
    }

    async getDocPrice(id) {
        const doc = await this.db.get('documents', id);
        return doc ? doc.price || 0 : 0;
    }

    async confirmPayment() {
        if (this.cart.length === 0) {
            this.showToast('Giỏ hàng trống', 'error');
            this.closeModal();
            return;
        }

        try {
            const userId = this.auth.currentUser.id;
            const total = this.cart.reduce((sum, id) => sum + (this.getDocPrice(id) || 0), 0);
            let discount = 0;
            
            if (this.voucherApplied) {
                discount = this.voucherApplied.type === 'percentage' ? 
                    total * this.voucherApplied.discount / 100 : 
                    this.voucherApplied.discount;
                    
                this.voucherApplied.used = true;
                this.voucherApplied.usedCount = (this.voucherApplied.usedCount || 0) + 1;
                await this.db.update('vouchers', this.voucherApplied);
            }

            // Create order
            const order = {
                id: this.db.generateId(),
                userId: userId,
                items: [...this.cart],
                total: total,
                discount: discount,
                finalTotal: Math.max(0, total - discount),
                status: 'completed',
                voucherCode: this.voucherApplied?.code || null,
                createdAt: new Date().toISOString(),
                fingerprint: Utils.getFingerprint()
            };
            await this.db.add('orders', order);

            // Create purchases
            for (const docId of this.cart) {
                const doc = await this.db.get('documents', docId);
                await this.db.add('purchases', {
                    id: this.db.generateId(),
                    userId: userId,
                    documentId: docId,
                    price: doc?.price || 0,
                    purchaseDate: new Date().toISOString(),
                    fingerprint: Utils.getFingerprint(),
                    status: 'completed',
                    orderId: order.id
                });
            }

            // Update user stats
            const user = await this.db.get('users', userId);
            if (user) {
                user.stats.totalPurchases = (user.stats.totalPurchases || 0) + this.cart.length;
                user.stats.totalSpent = (user.stats.totalSpent || 0) + order.finalTotal;
                await this.db.update('users', user);
            }

            // Audit log
            await this.db.add('auditLogs', {
                id: this.db.generateId(),
                userId: userId,
                action: 'purchase',
                details: `User purchased ${this.cart.length} documents, total: ${order.finalTotal}đ`,
                createdAt: new Date().toISOString()
            });

            // Notify user
            await this.addNotification(
                userId,
                '🎉 Thanh toán thành công!',
                `Bạn đã mua ${this.cart.length} tài liệu. Tổng tiền: ${order.finalTotal.toLocaleString()}đ`,
                '/#purchases'
            );

            // Clear cart
            this.cart = [];
            this.voucherApplied = null;
            localStorage.setItem(CONFIG.storagePrefix + 'cart', JSON.stringify(this.cart));
            this.updateCartUI();
            this.closeModal();
            
            this.showToast('Thanh toán thành công!', 'success');
            this.navigate('purchases');
        } catch (error) {
            this.showToast('Lỗi thanh toán: ' + error.message, 'error');
        }
    }

    // ============================================
    // RENDER: LOGIN
    // ============================================
    renderLogin(container) {
        container.innerHTML = `
            <div class="auth-page">
                <div class="auth-box">
                    <h2><i class="fas fa-shield-alt" style="color:var(--primary)"></i> Đăng nhập</h2>
                    <form id="loginForm" onsubmit="app.handleLogin(event)">
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" id="loginEmail" required placeholder="example@email.com">
                        </div>
                        <div class="form-group">
                            <label>Mật khẩu</label>
                            <input type="password" id="loginPassword" required placeholder="••••••••">
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">
                            <i class="fas fa-sign-in-alt"></i> Đăng nhập
                        </button>
                    </form>
                    <div class="auth-link">
                        Chưa có tài khoản? <a href="#" onclick="app.navigate('register')">Đăng ký ngay</a>
                    </div>
                    <div class="auth-link" style="margin-top:0.5rem;font-size:0.85rem;color:var(--gray-500);">
                        <i class="fas fa-info-circle"></i> Demo: admin@docsecure.com / Admin@2026#Secure
                    </div>
                </div>
            </div>
        `;
    }

    async handleLogin(event) {
        event.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        try {
            await this.auth.login(email, password);
            this.showToast('Đăng nhập thành công!', 'success');
            this.navigate('home');
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    // ============================================
    // RENDER: REGISTER
    // ============================================
    renderRegister(container) {
        container.innerHTML = `
            <div class="auth-page">
                <div class="auth-box">
                    <h2><i class="fas fa-user-plus" style="color:var(--primary)"></i> Đăng ký</h2>
                    <form id="registerForm" onsubmit="app.handleRegister(event)">
                        <div class="form-group">
                            <label>Tên đăng nhập</label>
                            <input type="text" id="regUsername" required placeholder="username" minlength="3">
                        </div>
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" id="regEmail" required placeholder="example@email.com">
                        </div>
                        <div class="form-group">
                            <label>Mật khẩu</label>
                            <input type="password" id="regPassword" required placeholder="••••••••" minlength="6">
                        </div>
                        <div class="form-group">
                            <label>Xác nhận mật khẩu</label>
                            <input type="password" id="regConfirm" required placeholder="••••••••">
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">
                            <i class="fas fa-user-check"></i> Đăng ký
                        </button>
                    </form>
                    <div class="auth-link">
                        Đã có tài khoản? <a href="#" onclick="app.navigate('login')">Đăng nhập</a>
                    </div>
                </div>
            </div>
        `;
    }

    async handleRegister(event) {
        event.preventDefault();
        const username = document.getElementById('regUsername').value;
        const email = document.getElementById('regEmail').value;
        const password = document.getElementById('regPassword').value;
        const confirm = document.getElementById('regConfirm').value;

        if (password !== confirm) {
            this.showToast('Mật khẩu xác nhận không khớp', 'error');
            return;
        }

        try {
            await this.auth.register({ username, email, password });
            this.showToast('Đăng ký thành công!', 'success');
            this.navigate('home');
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    // ============================================
    // RENDER: PROFILE
    // ============================================
    async renderProfile(container) {
        if (!this.auth.isLoggedIn()) {
            this.navigate('login');
            return;
        }

        const user = await this.db.get('users', this.auth.currentUser.id);
        if (!user) {
            this.navigate('home');
            return;
        }

        container.innerHTML = `
            <section class="documents-section">
                <div class="container">
                    <div class="page-header">
                        <h1><i class="fas fa-user"></i> Hồ sơ cá nhân</h1>
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 2fr;gap:2rem;">
                        <div style="background:var(--white);padding:2rem;border-radius:var(--radius);box-shadow:var(--shadow);text-align:center;">
                            <img src="${user.avatar || 'assets/images/default-avatar.png'}" 
                                 alt="${user.username}" 
                                 style="width:150px;height:150px;border-radius:50%;object-fit:cover;border:4px solid var(--primary);margin-bottom:1rem;"
                                 onerror="this.src='assets/images/default-avatar.png'">
                            <h3>${user.fullName || user.username}</h3>
                            <p style="color:var(--gray-500);">@${user.username}</p>
                            <div style="margin-top:1rem;">
                                <span class="status-badge active">
                                    <i class="fas fa-check-circle"></i> Đã xác thực
                                </span>
                            </div>
                            <div style="margin-top:1rem;display:flex;gap:0.5rem;justify-content:center;flex-wrap:wrap;">
                                <button class="btn btn-sm btn-outline" onclick="document.getElementById('avatarInput').click()">
                                    <i class="fas fa-camera"></i> Đổi ảnh
                                </button>
                                <input type="file" id="avatarInput" accept="image/*" style="display:none" onchange="app.uploadAvatar(event)">
                            </div>
                        </div>
                        <div>
                            <div style="background:var(--white);padding:2rem;border-radius:var(--radius);box-shadow:var(--shadow);">
                                <h4 style="margin-bottom:1rem;">Thống kê</h4>
                                <div class="admin-stats" style="margin-bottom:1.5rem;">
                                    <div class="stat-card">
                                        <div class="stat-label">Đã mua</div>
                                        <div class="stat-value">${user.stats?.totalPurchases || 0}</div>
                                    </div>
                                    <div class="stat-card">
                                        <div class="stat-label">Đã xem</div>
                                        <div class="stat-value">${user.stats?.documentsViewed || 0}</div>
                                    </div>
                                    <div class="stat-card">
                                        <div class="stat-label">Đã chi</div>
                                        <div class="stat-value">${(user.stats?.totalSpent || 0).toLocaleString()}đ</div>
                                    </div>
                                </div>
                                
                                <form id="profileForm" onsubmit="app.updateProfile(event)">
                                    <div class="form-group">
                                        <label>Họ và tên</label>
                                        <input type="text" id="profileFullName" value="${user.fullName || ''}">
                                    </div>
                                    <div class="form-group">
                                        <label>Email</label>
                                        <input type="email" id="profileEmail" value="${user.email}" disabled style="background:var(--gray-100);">
                                    </div>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save"></i> Cập nhật
                                    </button>
                                </form>
                                
                                <hr style="margin:1.5rem 0;">
                                
                                <h4 style="margin-bottom:1rem;">Đổi mật khẩu</h4>
                                <form id="changePassForm" onsubmit="app.changePassword(event)">
                                    <div class="form-group">
                                        <label>Mật khẩu hiện tại</label>
                                        <input type="password" id="currentPass" required>
                                    </div>
                                    <div class="form-group">
                                        <label>Mật khẩu mới</label>
                                        <input type="password" id="newPass" required minlength="6">
                                    </div>
                                    <div class="form-group">
                                        <label>Xác nhận mật khẩu mới</label>
                                        <input type="password" id="confirmNewPass" required>
                                    </div>
                                    <button type="submit" class="btn btn-danger">
                                        <i class="fas fa-key"></i> Đổi mật khẩu
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
        `;
    }

    async uploadAvatar(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = async (e) => {
            const user = await this.db.get('users', this.auth.currentUser.id);
            user.avatar = e.target.result;
            await this.db.update('users', user);
            this.auth.currentUser.avatar = e.target.result;
            this.auth.updateUI();
            this.showToast('Cập nhật avatar thành công!', 'success');
            this.navigate('profile');
        };
        reader.readAsDataURL(file);
    }

    async updateProfile(event) {
        event.preventDefault();
        const user = await this.db.get('users', this.auth.currentUser.id);
        user.fullName = document.getElementById('profileFullName').value;
        await this.db.update('users', user);
        this.showToast('Cập nhật hồ sơ thành công!', 'success');
    }

    async changePassword(event) {
        event.preventDefault();
        const current = document.getElementById('currentPass').value;
        const newPass = document.getElementById('newPass').value;
        const confirm = document.getElementById('confirmNewPass').value;

        if (newPass !== confirm) {
            this.showToast('Mật khẩu xác nhận không khớp', 'error');
            return;
        }

        const user = await this.db.get('users', this.auth.currentUser.id);
        if (Utils.hash(current) !== user.password) {
            this.showToast('Mật khẩu hiện tại không đúng', 'error');
            return;
        }

        user.password = Utils.hash(newPass);
        await this.db.update('users', user);
        this.showToast('Đổi mật khẩu thành công!', 'success');
        document.getElementById('changePassForm').reset();
    }

    // ============================================
    // RENDER: PURCHASES
    // ============================================
    async renderPurchases(container) {
        if (!this.auth.isLoggedIn()) {
            this.navigate('login');
            return;
        }

        const purchases = await this.db.query('purchases', 'userId', this.auth.currentUser.id);
        const completed = purchases.filter(p => p.status === 'completed');
        
        if (completed.length === 0) {
            container.innerHTML = `
                <section class="documents-section">
                    <div class="container text-center" style="padding:4rem 0;">
                        <i class="fas fa-shopping-bag" style="font-size:4rem;color:var(--gray-300);display:block;margin-bottom:1rem;"></i>
                        <h3>Chưa có tài liệu nào</h3>
                        <p style="color:var(--gray-500);">Bạn chưa mua tài liệu nào. Hãy khám phá thư viện!</p>
                        <a href="#" onclick="app.navigate('documents')" class="btn btn-primary" style="margin-top:1rem;">
                            <i class="fas fa-search"></i> Khám phá
                        </a>
                    </div>
                </section>
            `;
            return;
        }

        const docIds = completed.map(p => p.documentId);
        const docs = [];
        for (const id of docIds) {
            const doc = await this.db.get('documents', id);
            if (doc) {
                const purchase = completed.find(p => p.documentId === id);
                docs.push({ ...doc, purchaseDate: purchase?.purchaseDate });
            }
        }

        container.innerHTML = `
            <section class="documents-section">
                <div class="container">
                    <div class="page-header">
                        <h1><i class="fas fa-book"></i> Tài liệu đã mua (${docs.length})</h1>
                    </div>
                    <div class="document-grid">
                        ${docs.map(doc => `
                            <div class="document-card">
                                <div class="document-thumb">
                                    <i class="fas fa-file-pdf doc-icon"></i>
                                    <span class="document-badge free">Đã mua</span>
                                </div>
                                <div class="document-body">
                                    <h3><a href="#" onclick="app.viewDocument('${doc.id}')">${Utils.escapeHtml(doc.title)}</a></h3>
                                    <div class="document-meta">
                                        <span><i class="fas fa-calendar"></i> ${Utils.formatDate(doc.purchaseDate)}</span>
                                        <span><i class="fas fa-download"></i> ${doc.downloads || 0}</span>
                                    </div>
                                    <div class="document-footer">
                                        <span class="document-price free">
                                            <i class="fas fa-check-circle" style="color:var(--success)"></i> Đã sở hữu
                                        </span>
                                        <div class="document-actions">
                                            <button class="btn btn-sm btn-primary" onclick="app.viewDocument('${doc.id}')">
                                                <i class="fas fa-eye"></i> Xem
                                            </button>
                                            <button class="btn btn-sm btn-success" onclick="app.downloadDocument('${doc.id}')">
                                                <i class="fas fa-download"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </section>
        `;
    }

    // ============================================
    // RENDER: VIEW HISTORY
    // ============================================
    async renderViewHistory(container) {
        if (!this.auth.isLoggedIn()) {
            this.navigate('login');
            return;
        }

        const views = await this.db.query('views', 'userId', this.auth.currentUser.id);
        views.sort((a, b) => new Date(b.viewDate) - new Date(a.viewDate));

        if (views.length === 0) {
            container.innerHTML = `
                <section class="documents-section">
                    <div class="container text-center" style="padding:4rem 0;">
                        <i class="fas fa-history" style="font-size:4rem;color:var(--gray-300);display:block;margin-bottom:1rem;"></i>
                        <h3>Chưa có lịch sử xem</h3>
                        <p style="color:var(--gray-500);">Bạn chưa xem tài liệu nào.</p>
                        <a href="#" onclick="app.navigate('documents')" class="btn btn-primary" style="margin-top:1rem;">
                            <i class="fas fa-search"></i> Khám phá
                        </a>
                    </div>
                </section>
            `;
            return;
        }

        const docIds = views.map(v => v.documentId);
        const docs = [];
        for (const id of docIds) {
            const doc = await this.db.get('documents', id);
            if (doc) {
                const view = views.find(v => v.documentId === id);
                docs.push({ ...doc, viewDate: view?.viewDate });
            }
        }

        container.innerHTML = `
            <section class="documents-section">
                <div class="container">
                    <div class="page-header">
                        <h1><i class="fas fa-history"></i> Lịch sử xem (${docs.length})</h1>
                    </div>
                    <div class="document-grid">
                        ${docs.map(doc => `
                            <div class="document-card">
                                <div class="document-thumb">
                                    <i class="fas fa-file-pdf doc-icon"></i>
                                </div>
                                <div class="document-body">
                                    <h3><a href="#" onclick="app.viewDocument('${doc.id}')">${Utils.escapeHtml(doc.title)}</a></h3>
                                    <div class="document-meta">
                                        <span><i class="fas fa-clock"></i> ${Utils.formatDate(doc.viewDate)}</span>
                                        <span><i class="fas fa-eye"></i> ${doc.views || 0}</span>
                                    </div>
                                    <div class="document-footer">
                                        <span class="document-price ${!doc.price || doc.price === 0 ? 'free' : ''}">
                                            ${!doc.price || doc.price === 0 ? 'Miễn phí' : doc.price.toLocaleString() + 'đ'}
                                        </span>
                                        <div class="document-actions">
                                            <button class="btn btn-sm btn-primary" onclick="app.viewDocument('${doc.id}')">
                                                <i class="fas fa-eye"></i> Xem lại
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </section>
        `;
    }

    // ============================================
    // DOWNLOAD
    // ============================================
    async downloadDocument(id) {
        const doc = await this.db.get('documents', id);
        if (!doc) {
            this.showToast('Không tìm thấy tài liệu', 'error');
            return;
        }

        const hasAccess = await this.checkDocumentAccess(id);
        if (!hasAccess) {
            this.showToast('Bạn không có quyền tải tài liệu này', 'error');
            return;
        }

        const content = doc.content || 'Nội dung tài liệu';
        const user = this.auth.currentUser;
        const watermark = user ? 
            `\n\n---\n📄 Tài liệu: ${doc.title}\n👤 Người tải: ${user.username} (${user.email})\n🔒 Bảo vệ bởi DocSecure\n🕐 Thời gian: ${new Date().toISOString()}\n---\n` : '';

        const fileContent = content + watermark;
        const blob = new Blob([fileContent], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `${doc.title}.txt`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        doc.downloads = (doc.downloads || 0) + 1;
        await this.db.update('documents', doc);

        this.showToast('Tải xuống thành công!', 'success');
    }

    // ============================================
    // PWA SETUP
    // ============================================
    setupPWA() {
        // Register service worker
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('sw.js')
                .then(reg => console.log('SW registered:', reg))
                .catch(err => console.log('SW registration failed:', err));
        }

        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }

        // Install prompt
        let deferredPrompt;
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            this.showInstallPrompt();
        });
    }

    showInstallPrompt() {
        const modal = document.getElementById('modal');
        const body = document.getElementById('modalBody');
        
        body.innerHTML = `
            <div style="text-align:center;padding:1rem;">
                <i class="fas fa-download" style="font-size:3rem;color:var(--primary);display:block;margin-bottom:1rem;"></i>
                <h3>Cài đặt ứng dụng</h3>
                <p style="color:var(--gray-500);margin-bottom:1rem;">Cài đặt DocSecure để có trải nghiệm tốt hơn</p>
                <button class="btn btn-primary" onclick="app.installApp()">
                    <i class="fas fa-download"></i> Cài đặt
                </button>
                <button class="btn btn-outline" onclick="app.closeModal()" style="margin-left:0.5rem;">Để sau</button>
            </div>
        `;
        modal.classList.add('active');
    }

    installApp() {
        if (this.deferredPrompt) {
            this.deferredPrompt.prompt();
            this.deferredPrompt.userChoice.then(() => {
                this.deferredPrompt = null;
                this.closeModal();
            });
        }
    }

    // ============================================
    // SEARCH
    // ============================================
    toggleSearch() {
        document.getElementById('searchBar').classList.toggle('active');
        if (document.getElementById('searchBar').classList.contains('active')) {
            document.getElementById('searchInput').focus();
        }
    }

    toggleMobileMenu() {
        document.getElementById('mainNav').classList.toggle('show');
    }

    search() {
        const query = document.getElementById('searchInput').value.trim();
        if (query) {
            this.navigate('documents');
            setTimeout(() => {
                this.currentFilter.search = query;
                this.loadDocuments();
            }, 100);
        }
    }

    showHelp() {
        this.showToast('📚 Hướng dẫn sử dụng: Liên hệ admin@docsecure.com để được hỗ trợ', 'info');
    }

    // ============================================
    // UI HELPERS
    // ============================================
    showToast(message, type = 'info') {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = `toast ${type}`;
        toast.classList.add('show');
        clearTimeout(toast._timeout);
        toast._timeout = setTimeout(() => toast.classList.remove('show'), 4000);
    }

    closeModal() {
        document.getElementById('modal').classList.remove('active');
    }

    showLoading() {
        document.getElementById('loadingOverlay').classList.add('active');
    }

    hideLoading() {
        document.getElementById('loadingOverlay').classList.remove('active');
    }
}

// ============================================
// INITIALIZE
// ============================================
const app = new App();
window.app = app;
window.Utils = Utils;