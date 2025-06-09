// Application State
let currentUser = null;
let currentSection = 'notes';
let notes = [];
let passwords = [];
let editingItem = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already logged in
    const savedUser = sessionStorage.getItem('notelock_user');
    if (savedUser) {
        currentUser = JSON.parse(savedUser);
        showMainApp();
        loadUserData();
    }
    
    // Set up form handlers
    const signinForm = document.getElementById('signin-form');
    const registerForm = document.getElementById('register-form');
    const addForm = document.getElementById('add-form');
    
    if (signinForm) {
        signinForm.addEventListener('submit', handleSignIn);
    }
    
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    if (addForm) {
        addForm.addEventListener('submit', handleAddItem);
    }
    
    // Password strength checker for registration
    const registerPassword = document.getElementById('register-password');
    if (registerPassword) {
        registerPassword.addEventListener('input', checkPasswordStrength);
    }
    
    // Confirm password validation
    const confirmPassword = document.getElementById('confirm-password');
    if (confirmPassword) {
        confirmPassword.addEventListener('input', validatePasswordMatch);
    }
    
    // Modal backdrop click handler
    const modalBackdrop = document.querySelector('.modal-backdrop');
    if (modalBackdrop) {
        modalBackdrop.addEventListener('click', closeModal);
    }
    
    // Initialize sections
    showSection('notes');
});

// Authentication handling
function handleSignIn(e) {
    e.preventDefault();
    showLoading(true);
    
    const email = document.getElementById('signin-email').value;
    const password = document.getElementById('signin-password').value;
    
    // Simulate API call delay
    setTimeout(() => {
        signIn(email, password);
        showLoading(false);
    }, 1000);
}

function handleRegister(e) {
    e.preventDefault();
    
    const name = document.getElementById('register-name').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const agreeTerms = document.getElementById('agree-terms').checked;
    
    // Validation
    if (password !== confirmPassword) {
        showError('Passwords do not match');
        return;
    }
    
    if (!agreeTerms) {
        showError('Please agree to the Terms of Service and Privacy Policy');
        return;
    }
    
    if (getPasswordStrength(password) < 50) {
        showError('Please choose a stronger password');
        return;
    }
    
    showLoading(true);
    
    // Simulate API call delay
    setTimeout(() => {
        createAccount(name, email, password);
        showLoading(false);
    }, 1500);
}

function createAccount(name, email, password) {
    currentUser = { name, email, password };
    sessionStorage.setItem('notelock_user', JSON.stringify(currentUser));
    showMainApp();
    showSuccess('Account created successfully! Welcome to NoteLock.');
}

function signIn(email, password) {
    // In a real app, this would verify credentials against a backend
    currentUser = { email, password };
    sessionStorage.setItem('notelock_user', JSON.stringify(currentUser));
    showMainApp();
    loadUserData();
    showSuccess('Welcome back to NoteLock!');
}

function showMainApp() {
    document.getElementById('auth-screen').classList.add('hidden');
    document.getElementById('main-app').classList.remove('hidden');
    document.getElementById('add-btn').classList.remove('hidden');
    
    // Update user name in navigation
    const userName = document.getElementById('user-name');
    if (userName && currentUser.name) {
        userName.textContent = currentUser.name;
    } else if (userName && currentUser.email) {
        userName.textContent = currentUser.email.split('@')[0];
    }
    
    // Update counters
    updateCounters();
}

function logout() {
    if (confirm('Are you sure you want to sign out?')) {
        sessionStorage.removeItem('notelock_user');
        sessionStorage.removeItem('notelock_data_' + currentUser.email);
        currentUser = null;
        notes = [];
        passwords = [];
        
        document.getElementById('auth-screen').classList.remove('hidden');
        document.getElementById('main-app').classList.add('hidden');
        document.getElementById('add-btn').classList.add('hidden');
        
        // Reset forms
        document.getElementById('signin-form').reset();
        document.getElementById('register-form').reset();
        clearError();
    }
}

function switchToRegister() {
    document.getElementById('signin-form').classList.add('hidden');
    document.getElementById('register-form').classList.remove('hidden');
    clearError();
}

function switchToSignIn() {
    document.getElementById('register-form').classList.add('hidden');
    document.getElementById('signin-form').classList.remove('hidden');
    clearError();
}

// Password utilities
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const toggle = field.parentElement.querySelector('.password-toggle .eye-icon');
    
    if (field.type === 'password') {
        field.type = 'text';
        toggle.textContent = '🙈';
    } else {
        field.type = 'password';
        toggle.textContent = '👁️';
    }
}

function checkPasswordStrength(e) {
    const password = e.target.value;
    const strength = getPasswordStrength(password);
    
    const fill = document.getElementById('strength-fill');
    const text = document.getElementById('strength-text');
    
    if (fill) {
        fill.style.width = strength + '%';
        
        if (strength < 25) {
            fill.style.background = '#f44336';
            text.textContent = 'Password strength: Very Weak';
            text.style.color = '#f44336';
        } else if (strength < 50) {
            fill.style.background = '#ff9800';
            text.textContent = 'Password strength: Weak';
            text.style.color = '#ff9800';
        } else if (strength < 75) {
            fill.style.background = '#2196f3';
            text.textContent = 'Password strength: Good';
            text.style.color = '#2196f3';
        } else {
            fill.style.background = '#4caf50';
            text.textContent = 'Password strength: Strong';
            text.style.color = '#4caf50';
        }
    }
}

function getPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 8) strength += 25;
    if (password.length >= 12) strength += 10;
    if (password.match(/[a-z]/)) strength += 15;
    if (password.match(/[A-Z]/)) strength += 15;
    if (password.match(/[0-9]/)) strength += 15;
    if (password.match(/[^a-zA-Z0-9]/)) strength += 20;
    
    return Math.min(100, strength);
}

function validatePasswordMatch() {
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const icon = document.getElementById('confirm-icon');
    
    if (confirmPassword.length > 0) {
        if (password === confirmPassword) {
            icon.textContent = '✅';
        } else {
            icon.textContent = '❌';
        }
    } else {
        icon.textContent = '🔒';
    }
}

function generatePassword() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    
    // Ensure at least one of each type
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    password += lower.charAt(Math.floor(Math.random() * lower.length));
    password += upper.charAt(Math.floor(Math.random() * upper.length));
    password += numbers.charAt(Math.floor(Math.random() * numbers.length));
    password += symbols.charAt(Math.floor(Math.random() * symbols.length));
    
    // Fill the rest randomly
    for (let i = 4; i < 16; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    // Shuffle the password
    password = password.split('').sort(() => 0.5 - Math.random()).join('');
    
    document.getElementById('password').value = password;
    showSuccess('Strong password generated!');
}

// Section navigation
function showSection(section) {
    // Update navigation buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.section === section) {
            btn.classList.add('active');
        }
    });
    
    // Update sections
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    const targetSection = document.getElementById(section + '-section');
    if (targetSection) {
        targetSection.classList.add('active');
    }
    
    currentSection = section;
    updateCounters();
}

// Modal handling
function showAddModal() {
    const modal = document.getElementById('add-modal');
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
    updateModalForSection();
    editingItem = null;
}

function closeModal() {
    const modal = document.getElementById('add-modal');
    modal.classList.remove('active');
    document.body.style.overflow = '';
    document.getElementById('add-form').reset();
    editingItem = null;
    
    // Reset form groups visibility
    document.getElementById('note-content-group').classList.remove('hidden');
    document.getElementById('website-group').classList.add('hidden');
    document.getElementById('username-group').classList.add('hidden');
    document.getElementById('password-group').classList.add('hidden');
}

function updateModalForSection() {
    const isPasswordSection = currentSection === 'passwords';
    
    document.getElementById('modal-title').textContent = 
        editingItem ? (isPasswordSection ? 'Edit Password' : 'Edit Note') :
        (isPasswordSection ? 'Add New Password' : 'Add New Note');
    
    // Show/hide fields based on section
    document.getElementById('note-content-group').classList.toggle('hidden', isPasswordSection);
    document.getElementById('website-group').classList.toggle('hidden', !isPasswordSection);
    document.getElementById('username-group').classList.toggle('hidden', !isPasswordSection);
    document.getElementById('password-group').classList.toggle('hidden', !isPasswordSection);
}

// Add/Edit item handling
function handleAddItem(e) {
    e.preventDefault();
    
    const title = document.getElementById('item-title').value;
    
    if (currentSection === 'notes') {
        const content = document.getElementById('note-content').value;
        if (editingItem) {
            editNote(editingItem.id, title, content);
        } else {
            addNote(title, content);
        }
    } else {
        const website = document.getElementById('website').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        if (editingItem) {
            editPassword(editingItem.id, title, website, username, password);
        } else {
            addPassword(title, website, username, password);
        }
    }
    
    closeModal();
}

function addNote(title, content) {
    const note = {
        id: Date.now(),
        title,
        content,
        created: new Date().toLocaleString(),
        modified: new Date().toLocaleString()
    };
    
    notes.push(note);
    saveUserData();
    renderNotes();
    updateCounters();
    showSuccess('Note added successfully!');
}

function addPassword(title, website, username, password) {
    const passwordItem = {
        id: Date.now(),
        title,
        website,
        username,
        password,
        created: new Date().toLocaleString(),
        modified: new Date().toLocaleString()
    };
    
    passwords.push(passwordItem);
    saveUserData();
    renderPasswords();
    updateCounters();
    showSuccess('Password added successfully!');
}

// Render items
function renderNotes() {
    const container = document.getElementById('notes-list');
    
    if (notes.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📝</div>
                <h3>No notes yet</h3>
                <p>Your secure notes will appear here. Click the + button to create your first note!</p>
                <button class="btn btn-primary" onclick="showAddModal()">Add Your First Note</button>
            </div>
        `;
        return;
    }
    
    container.innerHTML = notes.map(note => `
        <div class="item-card">
            <div class="item-header">
                <h3 class="item-title">${escapeHtml(note.title)}</h3>
                <div class="item-actions">
                    <button class="action-btn edit-btn" onclick="startEditNote(${note.id})" title="Edit">
                        ✏️
                    </button>
                    <button class="action-btn copy-btn" onclick="copyToClipboard('${escapeHtml(note.content)}')" title="Copy">
                        📋
                    </button>
                    <button class="action-btn delete-btn" onclick="deleteNote(${note.id})" title="Delete">
                        🗑️
                    </button>
                </div>
            </div>
            <div class="item-content">${escapeHtml(note.content)}</div>
            <div class="item-meta">
                <span class="item-type">Note</span>
                <span class="item-date">${note.created}</span>
            </div>
        </div>
    `).join('');
}

function renderPasswords() {
    const container = document.getElementById('passwords-list');
    
    if (passwords.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">🔑</div>
                <h3>No passwords yet</h3>
                <p>Your secure passwords will appear here. Click the + button to add your first password!</p>
                <button class="btn btn-primary" onclick="showAddModal()">Add Your First Password</button>
            </div>
        `;
        return;
    }
    
    container.innerHTML = passwords.map(pwd => `
        <div class="item-card password-item">
            <div class="item-header">
                <h3 class="item-title">${escapeHtml(pwd.title)}</h3>
                <div class="item-actions">
                    <button class="action-btn edit-btn" onclick="startEditPassword(${pwd.id})" title="Edit">
                        ✏️
                    </button>
                    <button class="action-btn copy-btn" onclick="copyPassword(${pwd.id})" title="Copy Password">
                        📋
                    </button>
                    <button class="action-btn delete-btn" onclick="deletePassword(${pwd.id})" title="Delete">
                        🗑️
                    </button>
                </div>
            </div>
            <div class="item-content">
                <div class="password-field">
                    <strong>Website:</strong>
                    <span class="password-value">
                        ${pwd.website ? `<a href="${escapeHtml(pwd.website)}" target="_blank">${escapeHtml(pwd.website)}</a>` : 'Not specified'}
                    </span>
                </div>
                <div class="password-field">
                    <strong>Username:</strong>
                    <span class="password-value">${escapeHtml(pwd.username)}</span>
                </div>
                <div class="password-field">
                    <strong>Password:</strong>
                    <span class="password-value password-hidden" onclick="togglePasswordVisibility(this)">
                        ${'•'.repeat(pwd.password.length)}
                    </span>
                </div>
            </div>
            <div class="item-meta">
                <span class="item-type">Password</span>
                <span class="item-date">${pwd.created}</span>
            </div>
        </div>
    `).join('');
}

// Item actions
function startEditNote(id) {
    const note = notes.find(n => n.id === id);
    if (note) {
        editingItem = note;
        document.getElementById('item-title').value = note.title;
        document.getElementById('note-content').value = note.content;
        showAddModal();
    }
}

function startEditPassword(id) {
    const password = passwords.find(p => p.id === id);
    if (password) {
        editingItem = password;
        document.getElementById('item-title').value = password.title;
        document.getElementById('website').value = password.website;
        document.getElementById('username').value = password.username;
        document.getElementById('password').value = password.password;
        showAddModal();
    }
}

function editNote(id, title, content) {
    const noteIndex = notes.findIndex(n => n.id === id);
    if (noteIndex !== -1) {
        notes[noteIndex] = {
            ...notes[noteIndex],
            title,
            content,
            modified: new Date().toLocaleString()
        };
        saveUserData();
        renderNotes();
        showSuccess('Note updated successfully!');
    }
}

function editPassword(id, title, website, username, password) {
    const passwordIndex = passwords.findIndex(p => p.id === id);
    if (passwordIndex !== -1) {
        passwords[passwordIndex] = {
            ...passwords[passwordIndex],
            title,
            website,
            username,
            password,
            modified: new Date().toLocaleString()
        };
        saveUserData();
        renderPasswords();
        showSuccess('Password updated successfully!');
    }
}

function deleteNote(id) {
    if (confirm('Are you sure you want to delete this note? This action cannot be undone.')) {
        notes = notes.filter(note => note.id !== id);
        saveUserData();
        renderNotes();
        updateCounters();
        showSuccess('Note deleted successfully!');
    }
}

function deletePassword(id) {
    if (confirm('Are you sure you want to delete this password? This action cannot be undone.')) {
        passwords = passwords.filter(pwd => pwd.id !== id);
        saveUserData();
        renderPasswords();
        updateCounters();
        showSuccess('Password deleted successfully!');
    }
}

function copyPassword(id) {
    const password = passwords.find(pwd => pwd.id === id);
    if (password) {
        copyToClipboard(password.password);
        showSuccess('Password copied to clipboard!');
    }
}

function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showSuccess('Copied to clipboard!');
        }).catch(() => {
            fallbackCopyTextToClipboard(text);
        });
    } else {
        fallbackCopyTextToClipboard(text);
    }
}

function fallbackCopyTextToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    textArea.style.top = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showSuccess('Copied to clipboard!');
    } catch (err) {
        console.error('Could not copy text: ', err);
        showError('Could not copy to clipboard');
    }
    
    document.body.removeChild(textArea);
}

function togglePasswordVisibility(element) {
    const isHidden = element.classList.contains('password-hidden');
    if (isHidden) {
        // Find the actual password value
        const card = element.closest('.password-item');
        const title = card.querySelector('.item-title').textContent;
        const password = passwords.find(p => p.title === title);
        if (password) {
            element.textContent = password.password;
            element.classList.remove('password-hidden');
        }
    } else {
        const passwordLength = element.textContent.length;
        element.textContent = '•'.repeat(passwordLength);
        element.classList.add('password-hidden');
    }
}

// UI utilities
function showSuccess(message) {
    const toast = document.getElementById('success-toast');
    const messageEl = document.getElementById('success-message');
    
    messageEl.textContent = message;
    toast.classList.remove('hidden');
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 400);
    }, 3000);
}

function showError(message) {
    const errorEl = document.getElementById('error-message');
    const errorText = document.getElementById('error-text');
    
    errorText.textContent = message;
    errorEl.classList.remove('hidden');
    
    setTimeout(() => {
        errorEl.classList.add('hidden');
    }, 5000);
}

function clearError() {
    const errorEl = document.getElementById('error-message');
    errorEl.classList.add('hidden');
}

function showLoading(show) {
    const spinner = document.getElementById('loading-spinner');
    const forms = document.querySelectorAll('.auth-form');
    
    if (show) {
        spinner.classList.remove('hidden');
        forms.forEach(form => form.style.opacity = '0.5');
    } else {
        spinner.classList.add('hidden');
        forms.forEach(form => form.style.opacity = '1');
    }
}

function updateCounters() {
    const notesCount = document.getElementById('notes-count');
    const passwordsCount = document.getElementById('passwords-count');
    
    if (notesCount) {
        notesCount.textContent = `${notes.length} ${notes.length === 1 ? 'note' : 'notes'}`;
    }
    
    if (passwordsCount) {
        passwordsCount.textContent = `${passwords.length} ${passwords.length === 1 ? 'password' : 'passwords'}`;
    }
}

// Data persistence
function saveUserData() {
    if (!currentUser) return;
    
    const userData = {
        notes,
        passwords
    };
    
    // In a real application, this data would be encrypted before storage
    sessionStorage.setItem('notelock_data_' + currentUser.email, JSON.stringify(userData));
}

function loadUserData() {
    if (!currentUser) return;
    
    const savedData = sessionStorage.getItem('notelock_data_' + currentUser.email);
    if (savedData) {
        try {
            const userData = JSON.parse(savedData);
            notes = userData.notes || [];
            passwords = userData.passwords || [];
            
            renderNotes();
            renderPasswords();
            updateCounters();
        } catch (error) {
            console.error('Error loading user data:', error);
            notes = [];
            passwords = [];
        }
    }
}

// Security utilities
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + N for new item
    if ((e.ctrlKey || e.metaKey) && e.key === 'n' && !document.querySelector('.modal.active')) {
        e.preventDefault();
        if (currentUser) {
            showAddModal();
        }
    }
    
    // Escape to close modal
    if (e.key === 'Escape') {
        const modal = document.querySelector('.modal.active');
        if (modal) {
            closeModal();
        }
    }
});

// Initialize empty states on load
window.addEventListener('load', function() {
    if (currentUser) {
        renderNotes();
        renderPasswords();
        updateCounters();
    }
});





//NoteLock - Enhanced JavaScript with Backend Integration
class NoteLock {
    constructor() {
        this.currentUser = null;
        this.isAuthenticated = false;
        this.apiUrl = 'http://localhost:3000/api'; // Backend API URL
        this.notes = [];
        this.passwords = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkAuthStatus();
        this.initializeAnimations();
    }

    // Check if user is already authenticated
    async checkAuthStatus() {
        const token = localStorage.getItem('authToken');
        if (token) {
            try {
                const response = await this.apiCall('/auth/verify', 'POST', { token });
                if (response.success) {
                    this.currentUser = response.user;
                    this.isAuthenticated = true;
                    this.showMainApp();
                    await this.loadUserData();
                } else {
                    localStorage.removeItem('authToken');
                }
            } catch (error) {
                console.error('Auth verification failed:', error);
                localStorage.removeItem('authToken');
            }
        }
    }

    // API call helper function
    async apiCall(endpoint, method = 'GET', data = null) {
        const config = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
        };

        const token = localStorage.getItem('authToken');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }

        if (data) {
            config.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(this.apiUrl + endpoint, config);
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.message || 'API call failed');
            }
            
            return result;
        } catch (error) {
            // Fallback to local storage if backend is not available
            console.warn('Backend not available, using local storage:', error.message);
            return this.handleOfflineMode(endpoint, method, data);
        }
    }

    // Offline mode fallback
    handleOfflineMode(endpoint, method, data) {
        const offlineData = JSON.parse(localStorage.getItem('offlineData') || '{}');
        
        switch (endpoint) {
            case '/auth/login':
                return this.offlineLogin(data);
            case '/auth/register':
                return this.offlineRegister(data);
            case '/notes':
                if (method === 'GET') return { notes: offlineData.notes || [] };
                if (method === 'POST') return this.offlineAddNote(data);
                break;
            case '/passwords':
                if (method === 'GET') return { passwords: offlineData.passwords || [] };
                if (method === 'POST') return this.offlineAddPassword(data);
                break;
            default:
                return { success: false, message: 'Offline mode limited functionality' };
        }
    }

    // Offline authentication methods
    offlineLogin(data) {
        const users = JSON.parse(localStorage.getItem('offlineUsers') || '[]');
        const user = users.find(u => u.email === data.email && u.password === data.password);
        
        if (user) {
            const token = 'offline_' + Date.now();
            localStorage.setItem('authToken', token);
            return { success: true, user: { email: user.email }, token };
        }
        
        return { success: false, message: 'Invalid credentials' };
    }

    offlineRegister(data) {
        const users = JSON.parse(localStorage.getItem('offlineUsers') || '[]');
        
        if (users.find(u => u.email === data.email)) {
            return { success: false, message: 'Email already exists' };
        }
        
        const newUser = {
            id: Date.now(),
            email: data.email,
            password: data.password, // In real app, this would be hashed
            createdAt: new Date().toISOString()
        };
        
        users.push(newUser);
        localStorage.setItem('offlineUsers', JSON.stringify(users));
        
        const token = 'offline_' + Date.now();
        localStorage.setItem('authToken', token);
        
        return { success: true, user: { email: newUser.email }, token };
    }

    offlineAddNote(data) {
        const offlineData = JSON.parse(localStorage.getItem('offlineData') || '{}');
        if (!offlineData.notes) offlineData.notes = [];
        
        const newNote = {
            id: Date.now(),
            ...data,
            createdAt: new Date().toISOString()
        };
        
        offlineData.notes.push(newNote);
        localStorage.setItem('offlineData', JSON.stringify(offlineData));
        
        return { success: true, note: newNote };
    }

    offlineAddPassword(data) {
        const offlineData = JSON.parse(localStorage.getItem('offlineData') || '{}');
        if (!offlineData.passwords) offlineData.passwords = [];
        
        const newPassword = {
            id: Date.now(),
            ...data,
            createdAt: new Date().toISOString()
        };
        
        offlineData.passwords.push(newPassword);
        localStorage.setItem('offlineData', JSON.stringify(offlineData));
        
        return { success: true, password: newPassword };
    }

    // Setup event listeners
    setupEventListeners() {
        // Auth form submissions
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }
        
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        }

        // Navigation buttons
        document.addEventListener('click', (e) => {
            if (e.target.matches('.show-register')) {
                e.preventDefault();
                this.showRegisterForm();
            }
            
            if (e.target.matches('.show-login')) {
                e.preventDefault();
                this.showLoginForm();
            }
            
            if (e.target.matches('.logout-btn')) {
                e.preventDefault();
                this.handleLogout();
            }
        });

        // Password visibility toggles
        document.addEventListener('click', (e) => {
            if (e.target.matches('.password-toggle')) {
                this.togglePasswordVisibility(e.target);
            }
        });

        // Password strength checking
        document.addEventListener('input', (e) => {
            if (e.target.matches('input[type="password"]') && e.target.id !== 'loginPassword') {
                this.updatePasswordStrength(e.target);
            }
        });

        // Main app event listeners
        this.setupMainAppListeners();
    }

    setupMainAppListeners() {
        document.addEventListener('click', (e) => {
            // Tab switching
            if (e.target.matches('.tab-btn')) {
                this.switchTab(e.target.dataset.tab);
            }
            
            // Add new items
            if (e.target.matches('.add-note-btn')) {
                this.showAddNoteForm();
            }
            
            if (e.target.matches('.add-password-btn')) {
                this.showAddPasswordForm();
            }
            
            // Delete items
            if (e.target.matches('.delete-note')) {
                this.deleteNote(e.target.dataset.id);
            }
            
            if (e.target.matches('.delete-password')) {
                this.deletePassword(e.target.dataset.id);
            }
            
            // Copy password
            if (e.target.matches('.copy-password')) {
                this.copyPassword(e.target.dataset.password);
            }
            
            // Generate password
            if (e.target.matches('.generate-password')) {
                this.generatePassword();
            }
        });

        // Form submissions
        document.addEventListener('submit', (e) => {
            if (e.target.matches('#addNoteForm')) {
                e.preventDefault();
                this.handleAddNote(e.target);
            }
            
            if (e.target.matches('#addPasswordForm')) {
                e.preventDefault();
                this.handleAddPassword(e.target);
            }
        });
    }

    // Authentication handlers
    async handleLogin(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        const email = formData.get('email');
        const password = formData.get('password');

        this.showLoading('loginBtn');

        try {
            const response = await this.apiCall('/auth/login', 'POST', { email, password });
            
            if (response.success) {
                localStorage.setItem('authToken', response.token);
                this.currentUser = response.user;
                this.isAuthenticated = true;
                this.showMainApp();
                await this.loadUserData();
                this.showNotification('Login successful!', 'success');
            } else {
                this.showNotification(response.message || 'Login failed', 'error');
            }
        } catch (error) {
            this.showNotification('Login failed: ' + error.message, 'error');
        }

        this.hideLoading('loginBtn');
    }

    async handleRegister(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        const email = formData.get('email');
        const password = formData.get('password');
        const confirmPassword = formData.get('confirmPassword');

        if (password !== confirmPassword) {
            this.showNotification('Passwords do not match', 'error');
            return;
        }

        if (!this.isPasswordStrong(password)) {
            this.showNotification('Please choose a stronger password', 'error');
            return;
        }

        this.showLoading('registerBtn');

        try {
            const response = await this.apiCall('/auth/register', 'POST', { email, password });
            
            if (response.success) {
                localStorage.setItem('authToken', response.token);
                this.currentUser = response.user;
                this.isAuthenticated = true;
                this.showMainApp();
                this.showNotification('Registration successful!', 'success');
            } else {
                this.showNotification(response.message || 'Registration failed', 'error');
            }
        } catch (error) {
            this.showNotification('Registration failed: ' + error.message, 'error');
        }

        this.hideLoading('registerBtn');
    }

    handleLogout() {
        localStorage.removeItem('authToken');
        this.currentUser = null;
        this.isAuthenticated = false;
        this.notes = [];
        this.passwords = [];
        this.showAuthContainer();
        this.showNotification('Logged out successfully', 'success');
    }

    // Load user data
    async loadUserData() {
        try {
            const [notesResponse, passwordsResponse] = await Promise.all([
                this.apiCall('/notes'),
                this.apiCall('/passwords')
            ]);
            
            this.notes = notesResponse.notes || [];
            this.passwords = passwordsResponse.passwords || [];
            
            this.renderNotes();
            this.renderPasswords();
        } catch (error) {
            console.error('Failed to load user data:', error);
        }
    }

    // Note management
    async handleAddNote(form) {
        const formData = new FormData(form);
        const title = formData.get('title');
        const content = formData.get('content');

        try {
            const response = await this.apiCall('/notes', 'POST', { title, content });
            
            if (response.success) {
                this.notes.push(response.note);
                this.renderNotes();
                form.reset();
                this.hideModal();
                this.showNotification('Note added successfully', 'success');
            }
        } catch (error) {
            this.showNotification('Failed to add note: ' + error.message, 'error');
        }
    }

    async deleteNote(id) {
        if (!confirm('Are you sure you want to delete this note?')) return;

        try {
            const response = await this.apiCall(`/notes/${id}`, 'DELETE');
            
            if (response.success) {
                this.notes = this.notes.filter(note => note.id != id);
                this.renderNotes();
                this.showNotification('Note deleted successfully', 'success');
            }
        } catch (error) {
            this.showNotification('Failed to delete note: ' + error.message, 'error');
        }
    }

    // Password management
    async handleAddPassword(form) {
        const formData = new FormData(form);
        const website = formData.get('website');
        const username = formData.get('username');
        const password = formData.get('password');

        try {
            const response = await this.apiCall('/passwords', 'POST', { website, username, password });
            
            if (response.success) {
                this.passwords.push(response.password);
                this.renderPasswords();
                form.reset();
                this.hideModal();
                this.showNotification('Password added successfully', 'success');
            }
        } catch (error) {
            this.showNotification('Failed to add password: ' + error.message, 'error');
        }
    }

    async deletePassword(id) {
        if (!confirm('Are you sure you want to delete this password?')) return;

        try {
            const response = await this.apiCall(`/passwords/${id}`, 'DELETE');
            
            if (response.success) {
                this.passwords = this.passwords.filter(pass => pass.id != id);
                this.renderPasswords();
                this.showNotification('Password deleted successfully', 'success');
            }
        } catch (error) {
            this.showNotification('Failed to delete password: ' + error.message, 'error');
        }
    }

    // UI Methods
    showAuthContainer() {
        document.getElementById('authContainer').style.display = 'flex';
        document.getElementById('mainApp').style.display = 'none';
    }

    showMainApp() {
        document.getElementById('authContainer').style.display = 'none';
        document.getElementById('mainApp').style.display = 'block';
        
        if (this.currentUser) {
            document.getElementById('userEmail').textContent = this.currentUser.email;
        }
    }

    showLoginForm() {
        document.getElementById('loginCard').style.display = 'block';
        document.getElementById('registerCard').style.display = 'none';
    }

    showRegisterForm() {
        document.getElementById('loginCard').style.display = 'none';
        document.getElementById('registerCard').style.display = 'block';
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');
    }

    showAddNoteForm() {
        this.showModal(`
            <h3>Add New Note</h3>
            <form id="addNoteForm">
                <div class="form-group">
                    <label for="noteTitle">Title</label>
                    <input type="text" id="noteTitle" name="title" required>
                </div>
                <div class="form-group">
                    <label for="noteContent">Content</label>
                    <textarea id="noteContent" name="content" rows="5" required></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Add Note</button>
            </form>
        `);
    }

    showAddPasswordForm() {
        this.showModal(`
            <h3>Add New Password</h3>
            <form id="addPasswordForm">
                <div class="form-group">
                    <label for="passwordWebsite">Website</label>
                    <input type="text" id="passwordWebsite" name="website" required>
                </div>
                <div class="form-group">
                    <label for="passwordUsername">Username/Email</label>
                    <input type="text" id="passwordUsername" name="username" required>
                </div>
                <div class="form-group">
                    <label for="passwordPassword">Password</label>
                    <div class="input-wrapper">
                        <input type="password" id="passwordPassword" name="password" required>
                        <button type="button" class="generate-password">🎲</button>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">Add Password</button>
            </form>
        `);
    }

    showModal(content) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <span class="modal-close">&times;</span>
                ${content}
            </div>
        `;
        
        document.body.appendChild(modal);
        
        modal.querySelector('.modal-close').addEventListener('click', () => {
            this.hideModal();
        });
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.hideModal();
            }
        });
    }

    hideModal() {
        const modal = document.querySelector('.modal');
        if (modal) {
            modal.remove();
        }
    }

    // Password utilities
    generatePassword() {
        const length = 16;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        let password = '';
        
        for (let i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        
        const passwordInput = document.getElementById('passwordPassword');
        if (passwordInput) {
            passwordInput.value = password;
        }
    }

    async copyPassword(password) {
        try {
            await navigator.clipboard.writeText(password);
            this.showNotification('Password copied to clipboard', 'success');
        } catch (error) {
            this.showNotification('Failed to copy password', 'error');
        }
    }

    togglePasswordVisibility(button) {
        const input = button.parentElement.querySelector('input');
        const icon = button.querySelector('.eye-icon');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.textContent = '👁️‍🗨️';
        } else {
            input.type = 'password';
            icon.textContent = '👁️';
        }
    }

    updatePasswordStrength(input) {
        const password = input.value;
        const strength = this.calculatePasswordStrength(password);
        const strengthMeter = input.parentElement.parentElement.querySelector('.strength-fill');
        const strengthText = input.parentElement.parentElement.querySelector('.strength-text');
        
        if (strengthMeter && strengthText) {
            strengthMeter.style.width = strength.percentage + '%';
            strengthMeter.style.background = strength.color;
            strengthText.textContent = strength.text;
        }
    }

    calculatePasswordStrength(password) {
        let score = 0;
        
        if (password.length >= 8) score += 25;
        if (password.length >= 12) score += 25;
        if (/[a-z]/.test(password)) score += 10;
        if (/[A-Z]/.test(password)) score += 10;
        if (/[0-9]/.test(password)) score += 15;
        if (/[^A-Za-z0-9]/.test(password)) score += 15;
        
        if (score <= 40) {
            return { percentage: score, color: '#f44336', text: 'Weak' };
        } else if (score <= 70) {
            return { percentage: score, color: '#ff9800', text: 'Medium' };
        } else {
            return { percentage: score, color: '#4caf50', text: 'Strong' };
        }
    }

    isPasswordStrong(password) {
        return this.calculatePasswordStrength(password).percentage > 70;
    }

    // Render methods
    renderNotes() {
        const container = document.getElementById('notesContainer');
        if (!container) return;

        if (this.notes.length === 0) {
            container.innerHTML = '<p class="empty-state">No notes yet. Add your first note!</p>';
            return;
        }

        container.innerHTML = this.notes.map(note => `
            <div class="note-card">
                <h4>${this.escapeHtml(note.title)}</h4>
                <p>${this.escapeHtml(note.content)}</p>
                <div class="note-footer">
                    <small>${new Date(note.createdAt).toLocaleDateString()}</small>
                    <button class="delete-note" data-id="${note.id}">🗑️</button>
                </div>
            </div>
        `).join('');
    }

    renderPasswords() {
        const container = document.getElementById('passwordsContainer');
        if (!container) return;

        if (this.passwords.length === 0) {
            container.innerHTML = '<p class="empty-state">No passwords yet. Add your first password!</p>';
            return;
        }

        container.innerHTML = this.passwords.map(pass => `
            <div class="password-card">
                <h4>${this.escapeHtml(pass.website)}</h4>
                <p><strong>Username:</strong> ${this.escapeHtml(pass.username)}</p>
                <p><strong>Password:</strong> ••••••••</p>
                <div class="password-actions">
                    <button class="copy-password" data-password="${pass.password}">📋 Copy</button>
                    <button class="delete-password" data-id="${pass.id}">🗑️</button>
                </div>
            </div>
        `).join('');
    }

    // Utility methods
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showLoading(buttonId) {
        const button = document.getElementById(buttonId);
        if (button) {
            button.innerHTML = '<div class="btn-loader"></div> Loading...';
            button.disabled = true;
        }
    }

    hideLoading(buttonId) {
        const button = document.getElementById(buttonId);
        if (button) {
            const originalText = buttonId === 'loginBtn' ? 'Sign In' : 'Create Account';
            button.innerHTML = originalText;
            button.disabled = false;
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    // Initialize animations and effects
    initializeAnimations() {
        // Parallax effect for floating shapes
        window.addEventListener('mousemove', (e) => {
            const shapes = document.querySelectorAll('.floating-shape');
            const x = e.clientX / window.innerWidth;
            const y = e.clientY / window.innerHeight;
            
            shapes.forEach((shape, index) => {
                const speed = (index + 1) * 0.5;
                const xPos = (x - 0.5) * speed * 20;
                const yPos = (y - 0.5) * speed * 20;
                
                shape.style.transform = `translate(${xPos}px, ${yPos}px)`;
            });
        });

        // Smooth scrolling and entrance animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                }
            });
        }, observerOptions);

        // Observe elements for animation
        document.querySelectorAll('.note-card, .password-card, .auth-card').forEach(el => {
            observer.observe(el);
        });
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new NoteLock();
});



// Enhanced NoteLock Application with Google Sheets Backend Integration
class NoteLockApp {
    constructor() {
        this.currentUser = null;
        this.currentSection = 'notes';
        this.notes = [];
        this.passwords = [];
        this.editingItem = null;
        this.isOnline = navigator.onLine;
        this.syncQueue = [];
        
        // Backend configuration
        this.config = {
            apiUrl: 'https://your-backend-api.com/api', // Replace with your backend URL
            sheetsUrl: 'https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec', // Your Google Apps Script URL
            retryAttempts: 3,
            retryDelay: 1000
        };
        
        this.init();
    }

    // Initialize the application
    init() {
        this.setupEventListeners();
        this.setupNetworkMonitoring();
        this.checkAuthStatus();
        this.initializeAnimations();
        this.setupKeyboardShortcuts();
        this.loadOfflineData();
    }

    // Network monitoring for offline/online sync
    setupNetworkMonitoring() {
        window.addEventListener('online', () => {
            this.isOnline = true;
            this.showSuccess('Connection restored! Syncing data...');
            this.syncOfflineData();
        });

        window.addEventListener('offline', () => {
            this.isOnline = false;
            this.showError('Connection lost. Working in offline mode.');
        });
    }

    // Enhanced API call with retry logic and offline handling
    async apiCall(endpoint, method = 'GET', data = null, retries = 0) {
        if (!this.isOnline && retries === 0) {
            return this.handleOfflineOperation(endpoint, method, data);
        }

        const config = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': this.getApiKey(),
            },
        };

        const token = this.getAuthToken();
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }

        if (data) {
            config.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(this.config.apiUrl + endpoint, config);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            
            // Log successful operations to admin data
            this.logAdminActivity({
                action: `${method} ${endpoint}`,
                user: this.currentUser?.email || 'anonymous',
                timestamp: new Date().toISOString(),
                success: true,
                data: { endpoint, method, dataSize: JSON.stringify(data || {}).length }
            });
            
            return result;
        } catch (error) {
            console.error('API call failed:', error);
            
            // Log failed operations
            this.logAdminActivity({
                action: `${method} ${endpoint}`,
                user: this.currentUser?.email || 'anonymous',
                timestamp: new Date().toISOString(),
                success: false,
                error: error.message,
                data: { endpoint, method }
            });

            // Retry logic
            if (retries < this.config.retryAttempts) {
                await this.delay(this.config.retryDelay * (retries + 1));
                return this.apiCall(endpoint, method, data, retries + 1);
            }

            // Fallback to offline mode
            return this.handleOfflineOperation(endpoint, method, data);
        }
    }

    // Google Sheets integration
    async syncToGoogleSheets(operation, data) {
        try {
            const payload = {
                operation,
                data,
                timestamp: new Date().toISOString(),
                user: this.currentUser?.email || 'anonymous'
            };

            const response = await fetch(this.config.sheetsUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error('Google Sheets sync failed');
            }

            return await response.json();
        } catch (error) {
            console.error('Google Sheets sync error:', error);
            // Queue for later sync
            this.queueForSync(operation, data);
            throw error;
        }
    }

    // Enhanced authentication with backend validation
    async handleSignIn(e) {
        e.preventDefault();
        this.showLoading(true);
        
        const email = document.getElementById('signin-email').value;
        const password = document.getElementById('signin-password').value;
        
        try {
            const response = await this.apiCall('/auth/signin', 'POST', { 
                email, 
                password,
                userAgent: navigator.userAgent,
                timestamp: new Date().toISOString()
            });
            
            if (response.success) {
                this.currentUser = response.user;
                this.setAuthToken(response.token);
                this.showMainApp();
                await this.loadUserData();
                
                // Log successful login to admin data
                await this.syncToGoogleSheets('user_login', {
                    email: email,
                    loginTime: new Date().toISOString(),
                    userAgent: navigator.userAgent,
                    ipAddress: await this.getUserIP()
                });
                
                this.showSuccess('Welcome back to NoteLock!');
            } else {
                throw new Error(response.message || 'Invalid credentials');
            }
        } catch (error) {
            this.showError(error.message);
            
            // Log failed login attempt
            await this.syncToGoogleSheets('failed_login', {
                email: email,
                attemptTime: new Date().toISOString(),
                error: error.message,
                userAgent: navigator.userAgent
            });
        }
        
        this.showLoading(false);
    }

    async handleRegister(e) {
        e.preventDefault();
        
        const name = document.getElementById('register-name').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const agreeTerms = document.getElementById('agree-terms').checked;
        
        // Enhanced validation
        const validation = this.validateRegistration(name, email, password, confirmPassword, agreeTerms);
        if (!validation.valid) {
            this.showError(validation.message);
            return;
        }
        
        this.showLoading(true);
        
        try {
            const userData = {
                name,
                email,
                password,
                registrationDate: new Date().toISOString(),
                userAgent: navigator.userAgent,
                ipAddress: await this.getUserIP()
            };

            const response = await this.apiCall('/auth/register', 'POST', userData);
            
            if (response.success) {
                this.currentUser = response.user;
                this.setAuthToken(response.token);
                this.showMainApp();
                
                // Sync new user to Google Sheets
                await this.syncToGoogleSheets('user_registration', userData);
                
                this.showSuccess('Account created successfully! Welcome to NoteLock.');
            } else {
                throw new Error(response.message || 'Registration failed');
            }
        } catch (error) {
            this.showError(error.message);
        }
        
        this.showLoading(false);
    }

    // Enhanced note management with backend sync
    async addNote(title, content) {
        const noteData = {
            title,
            content,
            created: new Date().toISOString(),
            modified: new Date().toISOString(),
            userId: this.currentUser?.id,
            userEmail: this.currentUser?.email,
            category: 'note',
            encrypted: false // In production, implement encryption
        };

        try {
            const response = await this.apiCall('/notes', 'POST', noteData);
            
            if (response.success) {
                const note = { ...noteData, id: response.noteId };
                this.notes.push(note);
                
                // Sync to Google Sheets user data
                await this.syncToGoogleSheets('add_note', {
                    noteId: response.noteId,
                    title: title,
                    contentLength: content.length,
                    userId: this.currentUser?.id,
                    userEmail: this.currentUser?.email,
                    timestamp: new Date().toISOString()
                });
                
                this.saveOfflineData();
                this.renderNotes();
                this.updateCounters();
                this.showSuccess('Note added successfully!');
                
                return note;
            } else {
                throw new Error(response.message || 'Failed to add note');
            }
        } catch (error) {
            // Handle offline mode
            const offlineNote = { ...noteData, id: Date.now(), offline: true };
            this.notes.push(offlineNote);
            this.queueForSync('add_note', offlineNote);
            this.saveOfflineData();
            this.renderNotes();
            this.updateCounters();
            this.showError('Added offline. Will sync when connection is restored.');
            
            return offlineNote;
        }
    }

    async addPassword(title, website, username, password) {
        const passwordData = {
            title,
            website,
            username,
            password: await this.encryptPassword(password), // Encrypt before storing
            created: new Date().toISOString(),
            modified: new Date().toISOString(),
            userId: this.currentUser?.id,
            userEmail: this.currentUser?.email,
            category: 'password',
            strength: this.getPasswordStrength(password)
        };

        try {
            const response = await this.apiCall('/passwords', 'POST', passwordData);
            
            if (response.success) {
                const passwordItem = { ...passwordData, id: response.passwordId };
                this.passwords.push(passwordItem);
                
                // Sync to Google Sheets (without actual password for security)
                await this.syncToGoogleSheets('add_password', {
                    passwordId: response.passwordId,
                    title: title,
                    website: website,
                    username: username,
                    strength: passwordData.strength,
                    userId: this.currentUser?.id,
                    userEmail: this.currentUser?.email,
                    timestamp: new Date().toISOString()
                });
                
                this.saveOfflineData();
                this.renderPasswords();
                this.updateCounters();
                this.showSuccess('Password added successfully!');
                
                return passwordItem;
            } else {
                throw new Error(response.message || 'Failed to add password');
            }
        } catch (error) {
            // Handle offline mode
            const offlinePassword = { ...passwordData, id: Date.now(), offline: true };
            this.passwords.push(offlinePassword);
            this.queueForSync('add_password', offlinePassword);
            this.saveOfflineData();
            this.renderPasswords();
            this.updateCounters();
            this.showError('Added offline. Will sync when connection is restored.');
            
            return offlinePassword;
        }
    }

    // Enhanced data loading with caching
    async loadUserData() {
        try {
            this.showLoading(true);
            
            const [notesResponse, passwordsResponse] = await Promise.all([
                this.apiCall('/notes'),
                this.apiCall('/passwords')
            ]);
            
            this.notes = notesResponse.notes || [];
            this.passwords = passwordsResponse.passwords || [];
            
            // Decrypt passwords
            this.passwords = await Promise.all(
                this.passwords.map(async (pwd) => ({
                    ...pwd,
                    password: await this.decryptPassword(pwd.password)
                }))
            );
            
            this.saveOfflineData();
            this.renderNotes();
            this.renderPasswords();
            this.updateCounters();
            
            // Log data load activity
            await this.syncToGoogleSheets('data_load', {
                notesCount: this.notes.length,
                passwordsCount: this.passwords.length,
                userId: this.currentUser?.id,
                userEmail: this.currentUser?.email,
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            console.error('Failed to load user data:', error);
            this.loadOfflineData();
            this.showError('Loaded from offline storage');
        }
        
        this.showLoading(false);
    }

    // Enhanced delete operations with confirmation
    async deleteNote(id) {
        const note = this.notes.find(n => n.id === id);
        if (!note) return;

        if (!confirm(`Are you sure you want to delete "${note.title}"? This action cannot be undone.`)) {
            return;
        }

        try {
            const response = await this.apiCall(`/notes/${id}`, 'DELETE');
            
            if (response.success) {
                this.notes = this.notes.filter(n => n.id !== id);
                
                // Log deletion to Google Sheets
                await this.syncToGoogleSheets('delete_note', {
                    noteId: id,
                    title: note.title,
                    userId: this.currentUser?.id,
                    userEmail: this.currentUser?.email,
                    timestamp: new Date().toISOString()
                });
                
                this.saveOfflineData();
                this.renderNotes();
                this.updateCounters();
                this.showSuccess('Note deleted successfully!');
            } else {
                throw new Error(response.message || 'Failed to delete note');
            }
        } catch (error) {
            this.showError(error.message);
        }
    }

    async deletePassword(id) {
        const password = this.passwords.find(p => p.id === id);
        if (!password) return;

        if (!confirm(`Are you sure you want to delete the password for "${password.title}"? This action cannot be undone.`)) {
            return;
        }

        try {
            const response = await this.apiCall(`/passwords/${id}`, 'DELETE');
            
            if (response.success) {
                this.passwords = this.passwords.filter(p => p.id !== id);
                
                // Log deletion to Google Sheets
                await this.syncToGoogleSheets('delete_password', {
                    passwordId: id,
                    title: password.title,
                    website: password.website,
                    userId: this.currentUser?.id,
                    userEmail: this.currentUser?.email,
                    timestamp: new Date().toISOString()
                });
                
                this.saveOfflineData();
                this.renderPasswords();
                this.updateCounters();
                this.showSuccess('Password deleted successfully!');
            } else {
                throw new Error(response.message || 'Failed to delete password');
            }
        } catch (error) {
            this.showError(error.message);
        }
    }

    // Advanced search and filtering
    async searchItems(query, type = 'all') {
        const searchResults = {
            notes: [],
            passwords: []
        };

        if (type === 'all' || type === 'notes') {
            searchResults.notes = this.notes.filter(note =>
                note.title.toLowerCase().includes(query.toLowerCase()) ||
                note.content.toLowerCase().includes(query.toLowerCase())
            );
        }

        if (type === 'all' || type === 'passwords') {
            searchResults.passwords = this.passwords.filter(pwd =>
                pwd.title.toLowerCase().includes(query.toLowerCase()) ||
                pwd.website.toLowerCase().includes(query.toLowerCase()) ||
                pwd.username.toLowerCase().includes(query.toLowerCase())
            );
        }

        // Log search activity
        await this.syncToGoogleSheets('search_activity', {
            query: query,
            type: type,
            resultsCount: searchResults.notes.length + searchResults.passwords.length,
            userId: this.currentUser?.id,
            userEmail: this.currentUser?.email,
            timestamp: new Date().toISOString()
        });

        return searchResults;
    }

    // Data export functionality
    async exportData(format = 'json') {
        try {
            const exportData = {
                notes: this.notes.map(note => ({
                    ...note,
                    password: undefined // Remove sensitive data
                })),
                passwords: this.passwords.map(pwd => ({
                    ...pwd,
                    password: '***ENCRYPTED***' // Hide actual passwords
                })),
                exportDate: new Date().toISOString(),
                user: this.currentUser?.email
            };

            let blob, filename;

            if (format === 'json') {
                blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
                filename = `notelock-export-${new Date().toISOString().split('T')[0]}.json`;
            } else if (format === 'csv') {
                const csv = this.convertToCSV(exportData);
                blob = new Blob([csv], { type: 'text/csv' });
                filename = `notelock-export-${new Date().toISOString().split('T')[0]}.csv`;
            }

            // Create download link
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            // Log export activity
            await this.syncToGoogleSheets('data_export', {
                format: format,
                itemsCount: exportData.notes.length + exportData.passwords.length,
                userId: this.currentUser?.id,
                userEmail: this.currentUser?.email,
                timestamp: new Date().toISOString()
            });

            this.showSuccess(`Data exported successfully as ${format.toUpperCase()}!`);
        } catch (error) {
            console.error('Export failed:', error);
            this.showError('Failed to export data');
        }
    }

    // Utility functions
    async encryptPassword(password) {
        // In production, use proper encryption like AES
        // For demo purposes, using base64 encoding
        return btoa(password);
    }

    async decryptPassword(encryptedPassword) {
        try {
            return atob(encryptedPassword);
        } catch (error) {
            return encryptedPassword; // Return as-is if not encrypted
        }
    }

    async getUserIP() {
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip;
        } catch (error) {
            return 'unknown';
        }
    }

    validateRegistration(name, email, password, confirmPassword, agreeTerms) {
        if (!name.trim()) {
            return { valid: false, message: 'Name is required' };
        }

        if (!email.includes('@') || !email.includes('.')) {
            return { valid: false, message: 'Valid email is required' };
        }

        if (password !== confirmPassword) {
            return { valid: false, message: 'Passwords do not match' };
        }

        if (this.getPasswordStrength(password) < 60) {
            return { valid: false, message: 'Password is too weak' };
        }

        if (!agreeTerms) {
            return { valid: false, message: 'Please agree to the Terms of Service' };
        }

        return { valid: true };
    }

    // Offline data management
    saveOfflineData() {
        const data = {
            notes: this.notes,
            passwords: this.passwords,
            user: this.currentUser,
            lastSync: new Date().toISOString()
        };
        localStorage.setItem('notelock_offline_data', JSON.stringify(data));
    }

    loadOfflineData() {
        try {
            const data = JSON.parse(localStorage.getItem('notelock_offline_data') || '{}');
            this.notes = data.notes || [];
            this.passwords = data.passwords || [];
            
            if (this.notes.length > 0 || this.passwords.length > 0) {
                this.renderNotes();
                this.renderPasswords();
                this.updateCounters();
            }
        } catch (error) {
            console.error('Failed to load offline data:', error);
        }
    }

    queueForSync(operation, data) {
        this.syncQueue.push({ operation, data, timestamp: new Date().toISOString() });
        localStorage.setItem('notelock_sync_queue', JSON.stringify(this.syncQueue));
    }

    async syncOfflineData() {
        const queueData = localStorage.getItem('notelock_sync_queue');
        if (!queueData) return;

        try {
            const queue = JSON.parse(queueData);
            
            for (const item of queue) {
                await this.syncToGoogleSheets(item.operation, item.data);
            }
            
            // Clear sync queue
            this.syncQueue = [];
            localStorage.removeItem('notelock_sync_queue');
            
            this.showSuccess('Offline data synced successfully!');
        } catch (error) {
            console.error('Sync failed:', error);
            this.showError('Some data could not be synced');
        }
    }

    // Admin logging
    async logAdminActivity(activity) {
        try {
            await this.syncToGoogleSheets('admin_log', {
                ...activity,
                sessionId: this.getSessionId(),
                browserInfo: {
                    userAgent: navigator.userAgent,
                    language: navigator.language,
                    platform: navigator.platform
                }
            });
        } catch (error) {
            console.error('Failed to log admin activity:', error);
        }
    }

    // Helper functions
    getAuthToken() {
        return localStorage.getItem('notelock_auth_token');
    }

    setAuthToken(token) {
        localStorage.setItem('notelock_auth_token', token);
    }

    getApiKey() {
        return 'your-api-key-here'; // Replace with your actual API key
    }

    getSessionId() {
        let sessionId = sessionStorage.getItem('notelock_session_id');
        if (!sessionId) {
            sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
            sessionStorage.setItem('notelock_session_id', sessionId);
        }
        return sessionId;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    convertToCSV(data) {
        // Simple CSV conversion
        const csvRows = [];
        
        // Add notes
        csvRows.push('Type,Title,Content,Website,Username,Created,Modified');
        
        data.notes.forEach(note => {
            csvRows.push(`Note,"${note.title}","${note.content}",,,"${note.created}","${note.modified}"`);
        });
        
        data.passwords.forEach(pwd => {
            csvRows.push(`Password,"${pwd.title}",,"${pwd.website}","${pwd.username}","${pwd.created}","${pwd.modified}"`);
        });
        
        return csvRows.join('\n');
    }

    // Initialize enhanced event listeners
    setupEventListeners() {
        document.addEventListener('DOMContentLoaded', () => {
            // Enhanced form handling with real-time validation
            this.setupFormValidation();
            this.setupModalHandling();
            this.setupSearchFunctionality();
            this.setupExportFunctionality();
        });
    }

    setupFormValidation() {
        // Real-time email validation
        const emailInputs = document.querySelectorAll('input[type="email"]');
        emailInputs.forEach(input => {
            input.addEventListener('input', (e) => {
                this.validateEmailRealTime(e.target);
            });
        });
    }

    setupSearchFunctionality() {
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.performSearch(e.target.value);
                }, 300);
            });
        }
    }

    setupExportFunctionality() {
        const exportBtn = document.getElementById('export-btn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.showExportModal();
            });
        }
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + N for new item
            if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
                e.preventDefault();
                this.showAddModal();
            }
            
            // Ctrl/Cmd + F for search
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
                e.preventDefault();
                const searchInput = document.getElementById('search-input');
                if (searchInput) searchInput.focus();
            }
            
            // Ctrl/Cmd + E for export
            if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
                e.preventDefault();
                this.showExportModal();
            }
        });
    }

    // Enhanced error handling
    handleError(error, context = '') {
        console.error(`Error in ${context}:`, error);
        
        const errorMessage = error.message || 'An unexpected error occurred';
        this.showError(errorMessage);
        
        // Log error to admin data
        this.logAdminActivity({
            action: 'error',
            context: context,
            error: errorMessage,
            timestamp: new Date().toISOString(),
            user: this.currentUser?.email || 'anonymous'
        });
    }
}

// Google Apps Script Integration Helper
class GoogleSheetsIntegration {
    constructor(scriptUrl) {
        this.scriptUrl = scriptUrl;
    }

    async writeToSheet(sheetName, data) {
        const payload = {
            action: 'write',
            sheetName: sheetName,
            data: data
        };

        try {
            const response = await fetch(this.scriptUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });

            return await response.json();
        } catch (error) {
            console.error('Google Sheets write error:', error);
            throw error;
        }
    }

    async readFromSheet(sheetName, range = null) {
        const payload = {
            action: 'read',
            sheetName: sheetName,
            range: range
        };

        try {
            const response = await fetch(this.scriptUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });

            return await response.json();
        } catch (error) {
            console.error('Google Sheets read error:', error);
            throw error;
        }
    }
}

// Initialize the enhanced application
document.addEventListener('DOMContentLoaded', () => {
    window.noteLockApp = new NoteLockApp();
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { NoteLockApp, GoogleSheetsIntegration };
}


// Google Apps Script Backend for NoteLock Application
// This script handles all backend operations and syncs data to Google Sheets

// Configuration
const CONFIG = {
  ADMIN_SHEET_ID: 'YOUR_ADMIN_SHEET_ID', // Replace with your admin Google Sheet ID
  USER_SHEET_ID: 'YOUR_USER_SHEET_ID',   // Replace with your user data Google Sheet ID
  API_KEY: 'your-secret-api-key',        // Replace with your secure API key
  ENCRYPTION_KEY: 'your-encryption-key', // Replace with your encryption key
  MAX_REQUESTS_PER_MINUTE: 100,
  RATE_LIMIT_CACHE_KEY: 'rate_limit_',
};


