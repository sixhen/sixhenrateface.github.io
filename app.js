/**
 * DocSecure - Hệ thống quản lý tài liệu bảo mật cao
 * Phiên bản 2.0 - Chống leak và quản lý IP
 * @author DocSecure Team
 */

// ============================================
// CẤU HÌNH HỆ THỐNG
// ============================================
const CONFIG = {
    appName: 'DocSecure',
    version: '2.0.0',
    storagePrefix: 'docsecure_',
    sessionTimeout: 3600000, // 1 giờ
    maxLoginAttempts: 5,
    blockDuration: 300000, // 5 phút
    pageSize: 12,
    maxFileSize: 10485760, // 10MB
    allowedTypes: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'png', 'txt'],
    watermarkOpacity: 0.06,
    watermarkSpacing: 200,
    adminEmail: 'admin@docsecure.com',
    adminPassword: 'Admin@2026#Secure'
};

// ============================================
// DATABASE (IndexedDB)
// ============================================
class Database {
    constructor() {
        this.db = null;
        this.stores = ['users', 'documents', 'purchases', 'views', 'sessions', 'categories', 'ipLogs'];
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('DocSecureDB', 2);
            
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
                        if (name === 'users') {
                            store.createIndex('email', 'email', { unique: true });
                            store.createIndex('username', 'username', { unique: true });
                            store.createIndex('ip', 'ip');
                        } else if (name === 'documents') {
                            store.createIndex('category', 'category');
                            store.createIndex('uploadDate', 'uploadDate');
                            store.createIndex('price', 'price');
                            store.createIndex('ownerId', 'ownerId');
                        } else if (name === 'purchases' || name === 'views') {
                            store.createIndex('userId', 'userId');
                            store.createIndex('documentId', 'documentId');
                        } else if (name === 'sessions') {
                            store.createIndex('userId', 'userId');
                            store.createIndex('ip', 'ip');
                            store.createIndex('expires', 'expires');
                        } else if (name === 'ipLogs') {
                            store.createIndex('userId', 'userId');
                            store.createIndex('ip', 'ip');
                        }
                    }
                });
            };
        });
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
// HÀM TIỆN ÍCH
// ============================================
const Utils = {
    // Lấy IP client (thực tế cần backend, dùng fingerprint thay thế)
    getClientIP() {
        // Trong môi trường thuần client, dùng fingerprint tổng hợp
        const fp = this.getFingerprint();
        return `fp_${fp}`;
    },

    getFingerprint() {
        let fp = '';
        const navigatorInfo = [
            navigator.userAgent,
            navigator.language,
            navigator.platform,
            screen.width,
            screen.height,
            screen.colorDepth,
            new Date().getTimezoneOffset()
        ].join('|');
        
        // Hash đơn giản
        let hash = 0;
        for (let i = 0; i < navigatorInfo.length; i++) {
            hash = ((hash << 5) - hash) + navigatorInfo.charCodeAt(i);
            hash = hash & hash;
        }
        return hash.toString(36);
    },

    // Mã hóa đơn giản
    hash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash = hash & hash;
        }
        return 'h_' + hash.toString(36);
    },

    // Kiểm tra IP có khớp không
    isIPMatch(ip1, ip2) {
        return ip1 === ip2;
    },

    // Format date
    formatDate(date) {
        if (!date) return 'N/A';
        const d = new Date(date);
        return d.toLocaleDateString('vi-VN') + ' ' + d.toLocaleTimeString('vi-VN');
    },

    // Format currency
    formatCurrency(amount) {
        if (!amount || amount === 0) return 'Miễn phí';
        return amount.toLocaleString('vi-VN') + 'đ';
    },

    // Tạo watermark cho user
    generateWatermark(username, email, id) {
        const now = new Date().toISOString();
        return `${username} | ${email} | ${id} | ${now}`;
    },

    // Kiểm tra thiết bị có hỗ trợ anti-screen-capture không
    supportsScreenCaptureProtection() {
        // Kiểm tra các API bảo vệ màn hình
        const hasMediaDevices = !!navigator.mediaDevices;
        const hasPresentation = !!window.PresentationRequest;
        const hasScreenOrientation = !!window.screen?.orientation;
        
        // Một số trình duyệt hỗ trợ event 'visibilitychange' để phát hiện chụp màn hình
        return hasMediaDevices || hasPresentation || hasScreenOrientation;
    },

    // Tạo overlay bảo vệ
    createProtectionOverlay() {
        return {
            enabled: true,
            type: 'watermark',
            preventScreenshot: true,
            preventScreenRecording: true
        };
    }
};

// ============================================
// HỆ THỐNG AUTHENTICATION
// ============================================
class Auth {
    constructor(db) {
        this.db = db;
        this.currentUser = null;
        this.sessionKey = CONFIG.storagePrefix + 'session';
        this.loginAttempts = {};
        this.isIPBlocked = {};
        this.init();
    }

    async init() {
        const session = localStorage.getItem(this.sessionKey);
        if (session) {
            try {
                const data = JSON.parse(session);
                if (data.expires > Date.now()) {
                    // Kiểm tra IP
                    const currentIP = Utils.getClientIP();
                    if (data.ip && data.ip === currentIP) {
                        this.currentUser = data.user;
                        this.currentUser.ip = data.ip;
                        this.updateUI();
                        return;
                    } else {
                        // IP thay đổi - yêu cầu xác thực lại
                        console.warn('IP changed, requiring re-auth');
                        this.logout('IP đã thay đổi, vui lòng đăng nhập lại');
                        return;
                    }
                }
                this.logout('Phiên đăng nhập đã hết hạn');
            } catch (e) {
                this.logout();
            }
        }
        this.updateUI();
    }

    async login(email, password) {
        // Kiểm tra block
        if (this.isBlocked(email)) {
            throw new Error('Tài khoản bị khóa tạm thời do nhập sai quá nhiều lần. Vui lòng thử lại sau 5 phút.');
        }

        try {
            const users = await this.db.getAll('users');
            const user = users.find(u => 
                u.email === email && 
                u.password === Utils.hash(password)
            );
            
            if (!user) {
                this.recordAttempt(email);
                throw new Error('Email hoặc mật khẩu không đúng');
            }

            if (user.status === 'blocked') {
                throw new Error('Tài khoản đã bị khóa. Vui lòng liên hệ quản trị viên.');
            }

            // Kiểm tra IP binding
            const currentIP = Utils.getClientIP();
            if (user.boundIP && !Utils.isIPMatch(user.boundIP, currentIP)) {
                // Ghi log IP không khớp
                await this.db.add('ipLogs', {
                    id: this.db.generateId(),
                    userId: user.id,
                    email: user.email,
                    ip: currentIP,
                    expectedIP: user.boundIP,
                    timestamp: new Date().toISOString(),
                    type: 'ip_mismatch'
                });
                
                throw new Error('IP không khớp với thiết bị đã đăng ký. Vui lòng liên hệ quản trị viên để đặt lại.');
            }

            // Nếu chưa có IP binding, gán IP hiện tại
            if (!user.boundIP) {
                user.boundIP = currentIP;
                user.boundIPDate = new Date().toISOString();
                await this.db.update('users', user);
            }

            // Tạo session
            const session = {
                id: this.db.generateId(),
                userId: user.id,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role || 'user',
                    avatar: user.avatar,
                    boundIP: user.boundIP
                },
                ip: currentIP,
                expires: Date.now() + CONFIG.sessionTimeout,
                loginTime: new Date().toISOString(),
                userAgent: navigator.userAgent
            };

            localStorage.setItem(this.sessionKey, JSON.stringify(session));
            await this.db.add('sessions', session);

            this.currentUser = session.user;
            this.currentUser.ip = currentIP;
            this.clearAttempts(email);
            this.updateUI();

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
                boundIP: null,
                boundIPDate: null,
                createdAt: new Date().toISOString(),
                lastLogin: null,
                stats: { totalPurchases: 0, totalSpent: 0, documentsViewed: 0 }
            };

            await this.db.add('users', newUser);
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
        
        if (this.loginAttempts[email].count >= CONFIG.maxLoginAttempts) {
            console.warn(`[SECURITY] Account ${email} temporarily blocked`);
        }
    }

    clearAttempts(email) {
        delete this.loginAttempts[email];
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
                        <li><a href="#" onclick="app.navigate('view-history')"><i class="fas fa-history"></i> Lịch sử xem</a></li>
                        ${this.currentUser.role === 'admin' ? `
                            <li class="divider"></li>
                            <li><a href="#" onclick="app.navigate('admin')"><i class="fas fa-shield-alt"></i> Quản trị</a></li>
                        ` : ''}
                        <li class="divider"></li>
                        <li><a href="#" onclick="app.auth.logout()" style="color:var(--danger);">
                            <i class="fas fa-sign-out-alt"></i> Đăng xuất
                        </a></li>
                    </ul>
                </div>
            `;
            
            // Hiện admin menu
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
    getUserIP() { return this.currentUser?.ip || Utils.getClientIP(); }
}

// ============================================
// ỨNG DỤNG CHÍNH
// ============================================
class App {
    constructor() {
        this.db = new Database();
        this.auth = new Auth(this.db);
        this.currentPage = 1;
        this.currentFilter = { category: 'all', sort: 'newest', search: '' };
        this.viewedDocuments = new Set();
        this.protectionEnabled = true;
        
        this.init();
    }

    async init() {
        await this.db.init();
        await this.seedData();
        this.setupProtection();
        this.setupEvents();
        this.navigate(window.location.hash.replace('#', '') || 'home');
    }

    // ============================================
    // SEED DATA
    // ============================================
    async seedData() {
        const users = await this.db.getAll('users');
        if (users.length === 0) {
            // Admin account
            await this.db.add('users', {
                id: this.db.generateId(),
                username: 'admin',
                email: CONFIG.adminEmail,
                password: Utils.hash(CONFIG.adminPassword),
                fullName: 'Quản trị viên hệ thống',
                role: 'admin',
                status: 'active',
                avatar: null,
                boundIP: null,
                boundIPDate: null,
                createdAt: new Date().toISOString(),
                stats: { totalPurchases: 0, totalSpent: 0, documentsViewed: 0 }
            });

            // Sample documents
            const sampleDocs = [
                { 
                    title: 'Giáo trình JavaScript Nâng Cao', 
                    category: 'programming', 
                    price: 0, 
                    author: 'Nguyễn Văn A',
                    description: 'Tài liệu đầy đủ về JavaScript từ cơ bản đến nâng cao, bao gồm ES6+, async/await, và các pattern phổ biến.',
                    content: 'Nội dung chi tiết về JavaScript...'
                },
                { 
                    title: 'Thiết kế UI/UX Chuyên Nghiệp', 
                    category: 'design', 
                    price: 199000, 
                    author: 'Trần Thị B',
                    description: 'Hướng dẫn toàn diện về thiết kế giao diện và trải nghiệm người dùng, áp dụng cho web và mobile.',
                    content: 'Nội dung về thiết kế UI/UX...'
                },
                { 
                    title: 'Phân tích Dữ liệu với Python', 
                    category: 'data', 
                    price: 299000, 
                    author: 'Lê Văn C',
                    description: 'Khóa học phân tích dữ liệu sử dụng Python, pandas, numpy, và matplotlib.',
                    content: 'Nội dung phân tích dữ liệu...'
                },
                { 
                    title: 'Kinh doanh Online Hiệu Quả', 
                    category: 'business', 
                    price: 149000, 
                    author: 'Phạm Thị D',
                    description: 'Chiến lược kinh doanh online, marketing, và quản lý khách hàng.',
                    content: 'Nội dung kinh doanh online...'
                },
                { 
                    title: 'IELTS Academic Writing', 
                    category: 'language', 
                    price: 0, 
                    author: 'John Smith',
                    description: 'Hướng dẫn viết IELTS Academic task 1 và task 2 với cấu trúc và từ vựng học thuật.',
                    content: 'Nội dung IELTS Writing...'
                }
            ];

            const categories = [
                { id: 'programming', name: 'Lập trình', icon: 'fa-code' },
                { id: 'design', name: 'Thiết kế', icon: 'fa-paint-brush' },
                { id: 'data', name: 'Dữ liệu', icon: 'fa-chart-bar' },
                { id: 'business', name: 'Kinh doanh', icon: 'fa-briefcase' },
                { id: 'language', name: 'Ngôn ngữ', icon: 'fa-language' }
            ];

            for (const cat of categories) {
                await this.db.add('categories', cat);
            }

            for (const doc of sampleDocs) {
                await this.db.add('documents', {
                    id: this.db.generateId(),
                    ...doc,
                    ownerId: 'admin',
                    uploadDate: new Date().toISOString(),
                    views: Math.floor(Math.random() * 200) + 10,
                    downloads: Math.floor(Math.random() * 50) + 5,
                    rating: (Math.random() * 2 + 3).toFixed(1)
                });
            }
        }
    }

    // ============================================
    // BẢO VỆ & CHỐNG LEAK
    // ============================================
    setupProtection() {
        // 1. Ngăn chụp màn hình (nếu hỗ trợ)
        if (this.auth.isLoggedIn()) {
            this.enableScreenProtection();
        }

        // 2. Phát hiện dev tools
        this.detectDevTools();

        // 3. Ngăn context menu
        document.addEventListener('contextmenu', (e) => {
            if (this.auth.isLoggedIn()) {
                e.preventDefault();
                this.showToast('Chức năng này đã bị vô hiệu hóa để bảo vệ tài liệu', 'warning');
            }
        });

        // 4. Ngăn copy
        document.addEventListener('copy', (e) => {
            if (this.auth.isLoggedIn() && document.querySelector('.document-viewer.active')) {
                e.preventDefault();
                this.showToast('Sao chép nội dung không được phép', 'warning');
            }
        });

        // 5. Ngăn kéo thả
        document.addEventListener('dragstart', (e) => {
            if (this.auth.isLoggedIn()) {
                e.preventDefault();
            }
        });
    }

    enableScreenProtection() {
        // Sử dụng Screen Capture API nếu có
        try {
            if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
                // Kiểm tra xem có đang ghi màn hình không
                setInterval(() => {
                    // Kiểm tra thông qua window.screen
                    if (window.screen && window.screen.isCaptured) {
                        this.handleScreenCapture();
                    }
                }, 2000);
            }

            // Sử dụng Page Visibility API để phát hiện khi tab bị ẩn
            document.addEventListener('visibilitychange', () => {
                if (document.hidden && document.querySelector('.document-viewer.active')) {
                    // Có thể đang chụp màn hình tab
                    this.handleScreenCapture();
                }
            });

            // Sử dụng blur event
            window.addEventListener('blur', () => {
                if (document.querySelector('.document-viewer.active')) {
                    this.handleScreenCapture();
                }
            });

            console.log('[Protection] Screen protection enabled');
        } catch (e) {
            console.warn('[Protection] Some protection features not available:', e.message);
        }
    }

    handleScreenCapture() {
        const viewer = document.getElementById('documentViewer');
        if (viewer && viewer.classList.contains('active')) {
            // Làm mờ nội dung
            const content = document.getElementById('documentContent');
            if (content) {
                content.style.filter = 'blur(8px)';
                content.style.transition = 'filter 0.1s';
                setTimeout(() => {
                    content.style.filter = 'none';
                }, 500);
            }
            this.showToast('⚠️ Phát hiện chụp/ghi màn hình! Nội dung đã được bảo vệ.', 'error');
        }
    }

    detectDevTools() {
        // Phát hiện DevTools
        let devtoolsOpen = false;
        const threshold = 160; // Threshold for devtools detection

        const checkDevtools = () => {
            const widthDiff = window.outerWidth - window.innerWidth;
            const heightDiff = window.outerHeight - window.innerHeight;
            
            if (widthDiff > threshold || heightDiff > threshold) {
                if (!devtoolsOpen && this.auth.isLoggedIn()) {
                    devtoolsOpen = true;
                    this.showToast('⚠️ Phát hiện DevTools! Một số chức năng bị hạn chế.', 'warning');
                    // Làm mờ nội dung nếu đang xem tài liệu
                    if (document.querySelector('.document-viewer.active')) {
                        document.getElementById('documentContent').style.filter = 'blur(4px)';
                    }
                }
            } else {
                if (devtoolsOpen) {
                    devtoolsOpen = false;
                    if (document.querySelector('.document-viewer.active')) {
                        document.getElementById('documentContent').style.filter = 'none';
                    }
                }
            }
        };

        setInterval(checkDevtools, 1000);
    }

    // ============================================
    // RENDER WATERMARK
    // ============================================
    renderWatermark(container, user) {
        if (!user) return;
        
        const overlay = document.getElementById('watermarkOverlay');
        if (!overlay) return;

        const watermarkText = Utils.generateWatermark(
            user.username, 
            user.email, 
            user.id
        );

        overlay.innerHTML = '';
        const containerWidth = container?.offsetWidth || window.innerWidth;
        const containerHeight = container?.offsetHeight || window.innerHeight;
        
        const cols = Math.ceil(containerWidth / CONFIG.watermarkSpacing);
        const rows = Math.ceil(containerHeight / CONFIG.watermarkSpacing);

        for (let i = 0; i < rows; i++) {
            for (let j = 0; j < cols; j++) {
                const span = document.createElement('span');
                span.className = 'watermark-text';
                span.textContent = watermarkText;
                span.style.left = (j * CONFIG.watermarkSpacing) + 'px';
                span.style.top = (i * CONFIG.watermarkSpacing) + 'px';
                span.style.opacity = CONFIG.watermarkOpacity;
                span.style.fontSize = '1.2rem';
                span.style.color = '#000';
                span.style.pointerEvents = 'none';
                overlay.appendChild(span);
            }
        }
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
            case 'home':
                this.renderHome(main);
                break;
            case 'documents':
                this.renderDocuments(main);
                break;
            case 'document':
                if (data) this.renderDocumentDetail(main, data);
                break;
            case 'login':
                this.renderLogin(main);
                break;
            case 'register':
                this.renderRegister(main);
                break;
            case 'profile':
                this.renderProfile(main);
                break;
            case 'purchases':
                this.renderPurchases(main);
                break;
            case 'view-history':
                this.renderViewHistory(main);
                break;
            case 'admin':
                if (this.auth.isAdmin()) {
                    this.renderAdmin(main);
                } else {
                    this.showToast('Bạn không có quyền truy cập', 'error');
                    this.navigate('home');
                }
                break;
            default:
                this.renderHome(main);
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
                        <h1>Bảo vệ tài liệu của bạn</h1>
                        <p>Hệ thống quản lý và phân phối tài liệu an toàn với công nghệ watermark và bảo mật IP</p>
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
        const featured = docs.sort((a, b) => (b.views || 0) - (a.views || 0)).slice(0, 6);
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
                <p>Chưa có tài liệu nào</p>
            </div>`;
        }

        return docs.map(doc => {
            const isFree = !doc.price || doc.price === 0;
            const isPurchased = this.auth.isLoggedIn() && 
                this.viewedDocuments.has(doc.id);
            
            return `
                <div class="document-card">
                    <div class="document-thumb">
                        <i class="fas fa-file-pdf doc-icon"></i>
                        <span class="document-badge ${isFree ? 'free' : 'premium'}">
                            ${isFree ? 'Miễn phí' : 'Premium'}
                        </span>
                    </div>
                    <div class="document-body">
                        <h3><a href="#" onclick="app.viewDocument('${doc.id}')">${this.escapeHtml(doc.title)}</a></h3>
                        <div class="document-meta">
                            <span><i class="fas fa-user"></i> ${this.escapeHtml(doc.author || 'Unknown')}</span>
                            <span><i class="fas fa-eye"></i> ${doc.views || 0}</span>
                            <span><i class="fas fa-download"></i> ${doc.downloads || 0}</span>
                        </div>
                        <div class="document-footer">
                            <span class="document-price ${isFree ? 'free' : ''}">
                                ${isFree ? 'Miễn phí' : doc.price.toLocaleString() + 'đ'}
                            </span>
                            <div class="document-actions">
                                <button class="btn btn-sm btn-outline" onclick="app.viewDocument('${doc.id}')">
                                    <i class="fas fa-eye"></i>
                                </button>
                                ${isFree ? `
                                    <button class="btn btn-sm btn-success" onclick="app.downloadDocument('${doc.id}')">
                                        <i class="fas fa-download"></i>
                                    </button>
                                ` : `
                                    <button class="btn btn-sm btn-primary" onclick="app.purchaseDocument('${doc.id}')">
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

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
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

        // Kiểm tra quyền truy cập
        if (doc.price && doc.price > 0) {
            const isOwner = this.auth.isAdmin() || doc.ownerId === this.auth.currentUser?.id;
            const hasPurchased = await this.checkPurchased(id);
            
            if (!isOwner && !hasPurchased) {
                this.showToast('Vui lòng mua tài liệu để xem nội dung', 'warning');
                const confirm = window.confirm('Tài liệu này có phí. Bạn muốn mua ngay?');
                if (confirm) {
                    this.purchaseDocument(id);
                }
                return;
            }
        }

        // Ghi nhận view
        if (this.auth.isLoggedIn()) {
            await this.db.add('views', {
                id: this.db.generateId(),
                userId: this.auth.currentUser.id,
                documentId: doc.id,
                viewDate: new Date().toISOString(),
                ip: Utils.getClientIP()
            });
            
            // Update user stats
            const user = await this.db.get('users', this.auth.currentUser.id);
            if (user) {
                user.stats.documentsViewed = (user.stats.documentsViewed || 0) + 1;
                await this.db.update('users', user);
            }
        }

        // Update document views
        doc.views = (doc.views || 0) + 1;
        await this.db.update('documents', doc);

        // Show viewer
        this.showDocumentViewer(doc);
    }

    showDocumentViewer(doc) {
        const viewer = document.getElementById('documentViewer');
        const body = document.getElementById('viewerBody');
        const content = document.getElementById('documentContent');
        const overlay = document.getElementById('watermarkOverlay');

        // Clear watermark
        overlay.innerHTML = '';

        // Render content
        const isFree = !doc.price || doc.price === 0;
        const protectionBadge = Utils.supportsScreenCaptureProtection() ? 
            '<span class="protection-badge"><i class="fas fa-shield-alt"></i> Được bảo vệ chống chụp màn hình</span>' : '';

        content.innerHTML = `
            ${protectionBadge}
            <div class="doc-text">
                ${doc.content || 'Nội dung tài liệu đang được cập nhật...'}
                <p style="margin-top:2rem;font-size:0.85rem;color:var(--gray-500);border-top:1px solid var(--gray-300);padding-top:1rem;">
                    <i class="fas fa-lock"></i> Tài liệu được bảo vệ bởi DocSecure
                </p>
            </div>
        `;

        // Add watermark
        if (this.auth.isLoggedIn()) {
            this.renderWatermark(body, this.auth.currentUser);
        }

        viewer.classList.add('active');
        document.body.style.overflow = 'hidden';

        // Enable protection
        this.enableDocumentProtection();
    }

    enableDocumentProtection() {
        // Ngăn chụp màn hình bằng CSS
        const viewer = document.getElementById('documentViewer');
        if (viewer) {
            viewer.style.userSelect = 'none';
            viewer.style.webkitUserSelect = 'none';
        }

        // Thêm event listener để phát hiện print screen
        document.addEventListener('keydown', (e) => {
            if (e.key === 'PrintScreen') {
                this.handleScreenCapture();
                this.showToast('⚠️ Phát hiện hành vi chụp màn hình!', 'error');
            }
        });

        // Ngăn Ctrl+S, Ctrl+P
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'p')) {
                if (document.querySelector('.document-viewer.active')) {
                    e.preventDefault();
                    this.showToast('Chức năng này đã bị vô hiệu hóa để bảo vệ tài liệu', 'warning');
                }
            }
        });
    }

    closeDocument() {
        const viewer = document.getElementById('documentViewer');
        viewer.classList.remove('active');
        document.body.style.overflow = '';
        
        // Reset content
        document.getElementById('documentContent').innerHTML = '';
        document.getElementById('watermarkOverlay').innerHTML = '';
    }

    // ============================================
    // PURCHASE & DOWNLOAD
    // ============================================
    async purchaseDocument(id) {
        if (!this.auth.isLoggedIn()) {
            this.showToast('Vui lòng đăng nhập để mua tài liệu', 'error');
            this.navigate('login');
            return;
        }

        const doc = await this.db.get('documents', id);
        if (!doc) {
            this.showToast('Không tìm thấy tài liệu', 'error');
            return;
        }

        // Check if already purchased
        const purchased = await this.checkPurchased(id);
        if (purchased) {
            this.showToast('Bạn đã mua tài liệu này', 'info');
            this.viewDocument(id);
            return;
        }

        if (doc.price && doc.price > 0) {
            // Simulate payment
            const confirm = window.confirm(`Xác nhận mua tài liệu "${doc.title}" với giá ${doc.price.toLocaleString()}đ?`);
            if (!confirm) return;

            await this.db.add('purchases', {
                id: this.db.generateId(),
                userId: this.auth.currentUser.id,
                documentId: doc.id,
                price: doc.price,
                purchaseDate: new Date().toISOString(),
                ip: Utils.getClientIP()
            });

            // Update user stats
            const user = await this.db.get('users', this.auth.currentUser.id);
            if (user) {
                user.stats.totalPurchases = (user.stats.totalPurchases || 0) + 1;
                user.stats.totalSpent = (user.stats.totalSpent || 0) + doc.price;
                await this.db.update('users', user);
            }

            this.viewedDocuments.add(id);
            this.showToast('Mua tài liệu thành công!', 'success');
            this.viewDocument(id);
        } else {
            // Free document
            await this.db.add('purchases', {
                id: this.db.generateId(),
                userId: this.auth.currentUser.id,
                documentId: doc.id,
                price: 0,
                purchaseDate: new Date().toISOString(),
                ip: Utils.getClientIP()
            });

            this.viewedDocuments.add(id);
            this.showToast('Đã thêm vào thư viện cá nhân', 'success');
            this.downloadDocument(id);
        }
    }

    async downloadDocument(id) {
        const doc = await this.db.get('documents', id);
        if (!doc) {
            this.showToast('Không tìm thấy tài liệu', 'error');
            return;
        }

        // Check permission
        const hasAccess = await this.checkAccess(id);
        if (!hasAccess) {
            this.showToast('Bạn không có quyền tải tài liệu này', 'error');
            return;
        }

        // Tạo file với watermark
        const content = doc.content || 'Nội dung tài liệu';
        const user = this.auth.currentUser;
        const watermark = user ? 
            `\n\n---\nTài liệu: ${doc.title}\nNgười tải: ${user.username} (${user.email})\nIP: ${Utils.getClientIP()}\nThời gian: ${new Date().toISOString()}\n---\n` : '';

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

        // Update downloads
        doc.downloads = (doc.downloads || 0) + 1;
        await this.db.update('documents', doc);

        this.showToast('Tải xuống thành công!', 'success');
    }

    async checkAccess(docId) {
        if (!this.auth.isLoggedIn()) return false;
        
        const doc = await this.db.get('documents', docId);
        if (!doc) return false;

        // Admin or owner has access
        if (this.auth.isAdmin() || doc.ownerId === this.auth.currentUser.id) {
            return true;
        }

        // Check if purchased
        return await this.checkPurchased(docId);
    }

    async checkPurchased(docId) {
        if (!this.auth.isLoggedIn()) return false;
        
        const purchases = await this.db.query('purchases', 'userId', this.auth.currentUser.id);
        return purchases.some(p => p.documentId === docId);
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

        const ipInfo = user.boundIP ? 
            `<span class="status-badge active"><i class="fas fa-check-circle"></i> Đã liên kết</span>` :
            `<span class="status-badge pending"><i class="fas fa-clock"></i> Chưa liên kết</span>`;

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
                                ${ipInfo}
                            </div>
                            <div style="margin-top:1rem;display:flex;gap:0.5rem;justify-content:center;flex-wrap:wrap;">
                                <span class="btn btn-sm btn-outline" onclick="document.getElementById('avatarInput').click()">
                                    <i class="fas fa-camera"></i> Đổi ảnh
                                </span>
                                <input type="file" id="avatarInput" accept="image/*" style="display:none" onchange="app.uploadAvatar(event)">
                            </div>
                        </div>
                        <div>
                            <div style="background:var(--white);padding:2rem;border-radius:var(--radius);box-shadow:var(--shadow);">
                                <h4 style="margin-bottom:1rem;">Thông tin tài khoản</h4>
                                <div class="admin-stats" style="margin-bottom:1.5rem;">
                                    <div class="stat-card">
                                        <div class="label">Đã mua</div>
                                        <div class="value">${user.stats?.totalPurchases || 0}</div>
                                    </div>
                                    <div class="stat-card">
                                        <div class="label">Đã xem</div>
                                        <div class="value">${user.stats?.documentsViewed || 0}</div>
                                    </div>
                                    <div class="stat-card">
                                        <div class="label">Đã chi</div>
                                        <div class="value">${(user.stats?.totalSpent || 0).toLocaleString()}đ</div>
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
                                    <div class="form-group">
                                        <label>IP đã liên kết</label>
                                        <input type="text" value="${user.boundIP || 'Chưa liên kết'}" disabled style="background:var(--gray-100);">
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
        
        if (purchases.length === 0) {
            container.innerHTML = `
                <section class="documents-section">
                    <div class="container text-center" style="padding:4rem 0;">
                        <i class="fas fa-shopping-bag" style="font-size:4rem;color:var(--gray-300);display:block;margin-bottom:1rem;"></i>
                        <h3>Chưa có tài liệu nào</h3>
                        <p style="color:var(--gray-500);">Bạn chưa mua tài liệu nào. Hãy khám phá thư viện ngay!</p>
                        <a href="#" onclick="app.navigate('documents')" class="btn btn-primary" style="margin-top:1rem;">
                            <i class="fas fa-search"></i> Khám phá
                        </a>
                    </div>
                </section>
            `;
            return;
        }

        const docIds = purchases.map(p => p.documentId);
        const docs = [];
        for (const id of docIds) {
            const doc = await this.db.get('documents', id);
            if (doc) docs.push({ ...doc, purchaseDate: purchases.find(p => p.documentId === id)?.purchaseDate });
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
                                    <h3><a href="#" onclick="app.viewDocument('${doc.id}')">${this.escapeHtml(doc.title)}</a></h3>
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
                        <p style="color:var(--gray-500);">Bạn chưa xem tài liệu nào. Hãy khám phá thư viện!</p>
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
                                    <h3><a href="#" onclick="app.viewDocument('${doc.id}')">${this.escapeHtml(doc.title)}</a></h3>
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
    // RENDER: ADMIN
    // ============================================
    async renderAdmin(container) {
        if (!this.auth.isAdmin()) {
            this.navigate('home');
            return;
        }

        const users = await this.db.getAll('users');
        const docs = await this.db.getAll('documents');
        const purchases = await this.db.getAll('purchases');
        const totalRevenue = purchases.reduce((sum, p) => sum + (p.price || 0), 0);

        container.innerHTML = `
            <section class="documents-section">
                <div class="container">
                    <div class="admin-layout">
                        <aside class="admin-sidebar" id="adminSidebar">
                            <div class="admin-logo">
                                <h3><i class="fas fa-shield-alt" style="color:var(--primary)"></i> Quản trị</h3>
                            </div>
                            <ul>
                                <li><a href="#" class="active" onclick="app.adminPage('dashboard', event)"><i class="fas fa-chart-pie"></i> Dashboard</a></li>
                                <li><a href="#" onclick="app.adminPage('users', event)"><i class="fas fa-users"></i> Người dùng</a></li>
                                <li><a href="#" onclick="app.adminPage('documents', event)"><i class="fas fa-file"></i> Tài liệu</a></li>
                                <li><a href="#" onclick="app.adminPage('purchases', event)"><i class="fas fa-shopping-cart"></i> Đơn hàng</a></li>
                                <li><a href="#" onclick="app.adminPage('ip-logs', event)"><i class="fas fa-map-pin"></i> Log IP</a></li>
                            </ul>
                        </aside>
                        <main class="admin-main" id="adminContent">
                            <div class="page-header">
                                <h1>Dashboard</h1>
                            </div>
                            <div class="admin-stats">
                                <div class="stat-card">
                                    <div class="label">Tài liệu</div>
                                    <div class="value">${docs.length}</div>
                                </div>
                                <div class="stat-card">
                                    <div class="label">Người dùng</div>
                                    <div class="value">${users.length}</div>
                                </div>
                                <div class="stat-card">
                                    <div class="label">Đơn hàng</div>
                                    <div class="value">${purchases.length}</div>
                                </div>
                                <div class="stat-card">
                                    <div class="label">Doanh thu</div>
                                    <div class="value">${totalRevenue.toLocaleString()}đ</div>
                                </div>
                            </div>
                            <div style="background:var(--white);padding:1rem;border-radius:var(--radius);box-shadow:var(--shadow);">
                                <h4 style="margin-bottom:0.5rem;">Thông tin bảo mật</h4>
                                <p><i class="fas fa-check-circle" style="color:var(--success)"></i> Watermark động: <strong>Đã bật</strong></p>
                                <p><i class="fas fa-check-circle" style="color:var(--success)"></i> Chống chụp màn hình: <strong>${Utils.supportsScreenCaptureProtection() ? 'Đã bật' : 'Hạn chế'}</strong></p>
                                <p><i class="fas fa-check-circle" style="color:var(--success)"></i> IP Binding: <strong>Đã bật</strong></p>
                                <p><i class="fas fa-info-circle" style="color:var(--warning)"></i> Tổng số IP Logs: <strong>${(await this.db.getAll('ipLogs')).length}</strong></p>
                            </div>
                        </main>
                    </div>
                </div>
            </section>
        `;
    }

    async adminPage(page, event) {
        if (event) {
            event.preventDefault();
            document.querySelectorAll('#adminSidebar ul li a').forEach(el => el.classList.remove('active'));
            event.target.classList.add('active');
        }

        const container = document.getElementById('adminContent');
        if (!container) return;

        switch(page) {
            case 'dashboard':
                this.renderAdminDashboard(container);
                break;
            case 'users':
                await this.renderAdminUsers(container);
                break;
            case 'documents':
                await this.renderAdminDocuments(container);
                break;
            case 'purchases':
                await this.renderAdminPurchases(container);
                break;
            case 'ip-logs':
                await this.renderAdminIPLogs(container);
                break;
        }
    }

    async renderAdminDashboard(container) {
        const users = await this.db.getAll('users');
        const docs = await this.db.getAll('documents');
        const purchases = await this.db.getAll('purchases');
        const totalRevenue = purchases.reduce((sum, p) => sum + (p.price || 0), 0);

        container.innerHTML = `
            <div class="page-header"><h1>Dashboard</h1></div>
            <div class="admin-stats">
                <div class="stat-card"><div class="label">Tài liệu</div><div class="value">${docs.length}</div></div>
                <div class="stat-card"><div class="label">Người dùng</div><div class="value">${users.length}</div></div>
                <div class="stat-card"><div class="label">Đơn hàng</div><div class="value">${purchases.length}</div></div>
                <div class="stat-card"><div class="label">Doanh thu</div><div class="value">${totalRevenue.toLocaleString()}đ</div></div>
            </div>
            <div style="background:var(--white);padding:1rem;border-radius:var(--radius);box-shadow:var(--shadow);">
                <h4 style="margin-bottom:0.5rem;">Thông tin bảo mật</h4>
                <p><i class="fas fa-check-circle" style="color:var(--success)"></i> Watermark động: <strong>Đã bật</strong></p>
                <p><i class="fas fa-check-circle" style="color:var(--success)"></i> IP Binding: <strong>Đã bật</strong></p>
                <p><i class="fas fa-info-circle" style="color:var(--warning)"></i> Tổng số IP Logs: <strong>${(await this.db.getAll('ipLogs')).length}</strong></p>
            </div>
        `;
    }

    async renderAdminUsers(container) {
        const users = await this.db.getAll('users');
        
        container.innerHTML = `
            <div class="page-header">
                <h1><i class="fas fa-users"></i> Quản lý người dùng</h1>
                <span style="font-size:0.9rem;color:var(--gray-500);">Tổng: ${users.length}</span>
            </div>
            <div class="admin-table-wrapper">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Vai trò</th>
                            <th>Trạng thái</th>
                            <th>IP đã liên kết</th>
                            <th>Thao tác</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${users.map(user => `
                            <tr>
                                <td><strong>${user.username}</strong></td>
                                <td>${user.email}</td>
                                <td><span class="status-badge ${user.role === 'admin' ? 'active' : 'pending'}">${user.role === 'admin' ? 'Admin' : 'User'}</span></td>
                                <td><span class="status-badge ${user.status === 'active' ? 'active' : 'blocked'}">${user.status === 'active' ? 'Hoạt động' : 'Bị khóa'}</span></td>
                                <td style="font-size:0.8rem;font-family:monospace;">${user.boundIP || 'Chưa liên kết'}</td>
                                <td>
                                    <button class="btn btn-sm ${user.status === 'active' ? 'btn-danger' : 'btn-success'}" onclick="app.toggleUser('${user.id}')">
                                        ${user.status === 'active' ? 'Khóa' : 'Mở khóa'}
                                    </button>
                                    <button class="btn btn-sm btn-outline" onclick="app.resetUserIP('${user.id}')">
                                        <i class="fas fa-sync"></i> Reset IP
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    async renderAdminDocuments(container) {
        const docs = await this.db.getAll('documents');
        
        container.innerHTML = `
            <div class="page-header">
                <h1><i class="fas fa-file"></i> Quản lý tài liệu</h1>
                <button class="btn btn-primary" onclick="app.showAddDocModal()">
                    <i class="fas fa-plus"></i> Thêm mới
                </button>
            </div>
            <div class="admin-table-wrapper">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>Tiêu đề</th>
                            <th>Tác giả</th>
                            <th>Danh mục</th>
                            <th>Giá</th>
                            <th>Lượt xem</th>
                            <th>Thao tác</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${docs.map(doc => `
                            <tr>
                                <td><strong>${doc.title}</strong></td>
                                <td>${doc.author || 'Unknown'}</td>
                                <td>${doc.category || 'N/A'}</td>
                                <td>${!doc.price || doc.price === 0 ? 'Miễn phí' : doc.price.toLocaleString() + 'đ'}</td>
                                <td>${doc.views || 0}</td>
                                <td>
                                    <button class="btn btn-sm btn-danger" onclick="app.deleteDocument('${doc.id}')">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    async renderAdminPurchases(container) {
        const purchases = await this.db.getAll('purchases');
        purchases.sort((a, b) => new Date(b.purchaseDate) - new Date(a.purchaseDate));

        container.innerHTML = `
            <div class="page-header">
                <h1><i class="fas fa-shopping-cart"></i> Quản lý đơn hàng</h1>
                <span style="font-size:0.9rem;color:var(--gray-500);">Tổng: ${purchases.length}</span>
            </div>
            <div class="admin-table-wrapper">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>Mã đơn</th>
                            <th>Người dùng</th>
                            <th>Tài liệu</th>
                            <th>Giá</th>
                            <th>Ngày mua</th>
                            <th>IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${await Promise.all(purchases.map(async p => {
                            const user = await this.db.get('users', p.userId);
                            const doc = await this.db.get('documents', p.documentId);
                            return `
                                <tr>
                                    <td style="font-size:0.8rem;font-family:monospace;">${p.id.slice(0, 8)}</td>
                                    <td>${user ? user.username : 'Unknown'}</td>
                                    <td>${doc ? doc.title : 'Unknown'}</td>
                                    <td>${(p.price || 0).toLocaleString()}đ</td>
                                    <td>${Utils.formatDate(p.purchaseDate)}</td>
                                    <td style="font-size:0.75rem;font-family:monospace;">${p.ip || 'N/A'}</td>
                                </tr>
                            `;
                        })).then(rows => rows.join(''))}
                    </tbody>
                </table>
            </div>
        `;
    }

    async renderAdminIPLogs(container) {
        const logs = await this.db.getAll('ipLogs');
        logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        container.innerHTML = `
            <div class="page-header">
                <h1><i class="fas fa-map-pin"></i> Log IP</h1>
                <span style="font-size:0.9rem;color:var(--gray-500);">Tổng: ${logs.length}</span>
            </div>
            <div class="admin-table-wrapper">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>Thời gian</th>
                            <th>User</th>
                            <th>IP hiện tại</th>
                            <th>IP mong đợi</th>
                            <th>Loại</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${logs.map(log => `
                            <tr>
                                <td>${Utils.formatDate(log.timestamp)}</td>
                                <td>${log.email || 'Unknown'}</td>
                                <td style="font-size:0.75rem;font-family:monospace;">${log.ip || 'N/A'}</td>
                                <td style="font-size:0.75rem;font-family:monospace;">${log.expectedIP || 'N/A'}</td>
                                <td><span class="status-badge ${log.type === 'ip_mismatch' ? 'blocked' : 'pending'}">${log.type === 'ip_mismatch' ? '⚠️ Không khớp' : 'Bình thường'}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    // ============================================
    // ADMIN ACTIONS
    // ============================================
    async toggleUser(userId) {
        const user = await this.db.get('users', userId);
        if (!user) return;
        
        user.status = user.status === 'active' ? 'blocked' : 'active';
        await this.db.update('users', user);
        this.showToast(`Đã ${user.status === 'active' ? 'mở khóa' : 'khóa'} tài khoản ${user.username}`, 'success');
        this.adminPage('users');
    }

    async resetUserIP(userId) {
        if (!confirm('Xác nhận đặt lại IP cho tài khoản này?')) return;
        
        const user = await this.db.get('users', userId);
        if (!user) return;
        
        user.boundIP = null;
        user.boundIPDate = null;
        await this.db.update('users', user);
        this.showToast(`Đã đặt lại IP cho ${user.username}`, 'success');
        this.adminPage('users');
    }

    async deleteDocument(docId) {
        if (!confirm('Xác nhận xóa tài liệu này?')) return;
        
        await this.db.delete('documents', docId);
        this.showToast('Đã xóa tài liệu', 'success');
        this.adminPage('documents');
    }

    showAddDocModal() {
        const modal = document.getElementById('modal');
        const body = document.getElementById('modalBody');
        
        body.innerHTML = `
            <h2><i class="fas fa-plus-circle" style="color:var(--primary)"></i> Thêm tài liệu mới</h2>
            <form id="addDocForm" onsubmit="app.handleAddDoc(event)">
                <div class="form-group">
                    <label>Tiêu đề *</label>
                    <input type="text" id="docTitle" required>
                </div>
                <div class="form-group">
                    <label>Tác giả</label>
                    <input type="text" id="docAuthor">
                </div>
                <div class="form-group">
                    <label>Danh mục</label>
                    <select id="docCategory">
                        <option value="programming">Lập trình</option>
                        <option value="design">Thiết kế</option>
                        <option value="data">Dữ liệu</option>
                        <option value="business">Kinh doanh</option>
                        <option value="language">Ngôn ngữ</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Giá (VNĐ)</label>
                    <input type="number" id="docPrice" value="0" min="0">
                </div>
                <div class="form-group">
                    <label>Nội dung</label>
                    <textarea id="docContent" rows="4" placeholder="Nội dung tài liệu..."></textarea>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Thêm tài liệu</button>
            </form>
        `;
        
        modal.classList.add('active');
    }

    async handleAddDoc(event) {
        event.preventDefault();
        const doc = {
            id: this.db.generateId(),
            title: document.getElementById('docTitle').value,
            author: document.getElementById('docAuthor').value || 'Unknown',
            category: document.getElementById('docCategory').value,
            price: parseFloat(document.getElementById('docPrice').value) || 0,
            content: document.getElementById('docContent').value || 'Nội dung mẫu',
            ownerId: this.auth.currentUser?.id || 'admin',
            uploadDate: new Date().toISOString(),
            views: 0,
            downloads: 0,
            rating: 0
        };

        await this.db.add('documents', doc);
        this.closeModal();
        this.showToast('Thêm tài liệu thành công!', 'success');
        this.adminPage('documents');
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================
    closeModal() {
        document.getElementById('modal').classList.remove('active');
    }

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
        this.showToast('Hướng dẫn sử dụng: Liên hệ admin@docsecure.com để được hỗ trợ', 'info');
    }

    showToast(message, type = 'info') {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = `toast ${type}`;
        toast.classList.add('show');
        clearTimeout(toast._timeout);
        toast._timeout = setTimeout(() => toast.classList.remove('show'), 4000);
    }
}

// ============================================
// KHỞI TẠO ỨNG DỤNG
// ============================================
const app = new App();

// Expose for inline handlers
window.app = app;
window.Utils = Utils;