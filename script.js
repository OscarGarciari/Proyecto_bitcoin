// BitWallet - Sistema Técnico y Funcional
hideAuthForms();
class BitWalletSystem {
    constructor() {
        this.currentUser = null;
        this.isAuthenticated = false;
        this.apiBaseUrl = 'https://api.bitwallet.com/v1';
        this.init();
    }

    init() {
        this.initializeEventListeners();
        this.checkExistingSession();
        this.initializeServiceWorker();
        this.setupPerformanceMonitoring();
    }

    // ===== SISTEMA DE AUTENTICACIÓN =====
    async handleLogin(event) {
        event.preventDefault();
        
        const formData = new FormData(event.target);
        const credentials = {
            email: formData.get('email').trim().toLowerCase(),
            password: formData.get('password')
        };

        try {
            this.showLoader('Verificando credenciales...');
            
            // Validación frontend
            if (!this.validateEmail(credentials.email)) {
                throw new Error('Formato de email inválido');
            }

            if (!this.validatePassword(credentials.password)) {
                throw new Error('La contraseña debe tener al menos 6 caracteres');
            }

            // Simulación de llamada API
            const authResult = await this.mockApiCall('/auth/login', credentials);
            
            if (authResult.success) {
                this.currentUser = authResult.user;
                this.isAuthenticated = true;
                
                // Guardar sesión
                this.setSession(authResult.token, authResult.user);
                
                // Analytics
                this.trackEvent('user_login_success');
                
                this.showNotification('¡Bienvenido! Sesión iniciada correctamente', 'success');
                this.redirectToDashboard();
            } else {
                throw new Error(authResult.message || 'Error en la autenticación');
            }

        } catch (error) {
            console.error('Login error:', error);
            this.trackEvent('user_login_failed', { error: error.message });
            this.showNotification(error.message, 'error');
        } finally {
            this.hideLoader();
        }
    }

    async handleRegister(event) {
        event.preventDefault();
        
        const formData = new FormData(event.target);
        const userData = {
            name: formData.get('name').trim(),
            email: formData.get('email').trim().toLowerCase(),
            password: formData.get('password'),
            confirmPassword: formData.get('confirmPassword'),
            business: formData.get('business').trim(),
            terms: formData.get('terms') === 'on'
        };

        try {
            this.showLoader('Creando tu cuenta...');

            // Validaciones
            const validation = this.validateRegistration(userData);
            if (!validation.isValid) {
                throw new Error(validation.errors.join(', '));
            }

            // Simulación de API
            const registerResult = await this.mockApiCall('/auth/register', userData);
            
            if (registerResult.success) {
                this.trackEvent('user_registration_success');
                this.showNotification('¡Cuenta creada exitosamente! Revisa tu email para verificar tu cuenta.', 'success');
                
                // Auto-login después del registro
                setTimeout(() => {
                    this.hideAuthForms();
                    this.showLogin();
                }, 2000);
            } else {
                throw new Error(registerResult.message || 'Error en el registro');
            }

        } catch (error) {
            console.error('Registration error:', error);
            this.trackEvent('user_registration_failed', { error: error.message });
            this.showNotification(error.message, 'error');
        } finally {
            this.hideLoader();
        }
    }

    // ===== VALIDACIONES AVANZADAS =====
    validateRegistration(userData) {
        const errors = [];

        if (!userData.name || userData.name.length < 2) {
            errors.push('El nombre debe tener al menos 2 caracteres');
        }

        if (!this.validateEmail(userData.email)) {
            errors.push('Email inválido');
        }

        if (!this.validatePassword(userData.password)) {
            errors.push('La contraseña debe tener al menos 6 caracteres');
        }

        if (userData.password !== userData.confirmPassword) {
            errors.push('Las contraseñas no coinciden');
        }

        if (!userData.business || userData.business.length < 2) {
            errors.push('El nombre del emprendimiento es requerido');
        }

        if (!userData.terms) {
            errors.push('Debes aceptar los términos y condiciones');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }

    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    validatePassword(password) {
        return password && password.length >= 6;
    }

    // ===== MANEJO DE SESIÓN =====
    setSession(token, user) {
        const sessionData = {
            token,
            user,
            timestamp: Date.now(),
            expiresIn: 24 * 60 * 60 * 1000 // 24 horas
        };

        // Almacenar en localStorage con encriptación básica
        const encryptedData = btoa(JSON.stringify(sessionData));
        localStorage.setItem('bitwallet_session', encryptedData);
        
        // Configurar headers para futuras requests
        this.setAuthHeader(token);
    }

    checkExistingSession() {
        try {
            const sessionData = localStorage.getItem('bitwallet_session');
            if (sessionData) {
                const decryptedData = JSON.parse(atob(sessionData));
                
                // Verificar expiración
                if (Date.now() - decryptedData.timestamp < decryptedData.expiresIn) {
                    this.currentUser = decryptedData.user;
                    this.isAuthenticated = true;
                    this.setAuthHeader(decryptedData.token);
                    this.updateUIForAuthenticatedUser();
                } else {
                    this.clearSession();
                }
            }
        } catch (error) {
            console.error('Error checking session:', error);
            this.clearSession();
        }
    }

    clearSession() {
        localStorage.removeItem('bitwallet_session');
        this.currentUser = null;
        this.isAuthenticated = false;
        this.removeAuthHeader();
        this.updateUIForUnauthenticatedUser();
    }

    // ===== INTERFAZ DE USUARIO =====
    showLoader(message = 'Cargando...') {
        const loader = document.createElement('div');
        loader.id = 'global-loader';
        loader.innerHTML = `
            <div class="loader-overlay">
                <div class="loader-content">
                    <div class="bitcoin-spinner"></div>
                    <p>${message}</p>
                </div>
            </div>
        `;
        document.body.appendChild(loader);
    }

    hideLoader() {
        const loader = document.getElementById('global-loader');
        if (loader) {
            loader.remove();
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <span class="notification-icon">${this.getNotificationIcon(type)}</span>
                <span class="notification-message">${message}</span>
                <button class="notification-close" onclick="this.parentElement.parentElement.remove()">&times;</button>
            </div>
        `;

        document.body.appendChild(notification);

        // Auto-remove después de 5 segundos
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    getNotificationIcon(type) {
        const icons = {
            success: '✓',
            error: '✕',
            warning: '⚠',
            info: 'ℹ'
        };
        return icons[type] || icons.info;
    }

    // ===== NAVEGACIÓN Y FORMULARIOS =====
    showLogin() {
        this.hideAllAuthForms();
        document.getElementById('loginForm').style.display = 'flex';
        this.trackEvent('auth_form_view', { form: 'login' });
    }

    showRegister() {
        this.hideAllAuthForms();
        document.getElementById('registerForm').style.display = 'flex';
        this.trackEvent('auth_form_view', { form: 'register' });
    }

    hideAuthForms() {
        this.hideAllAuthForms();
    }

    hideAllAuthForms() {
        const forms = document.querySelectorAll('.auth-form-container');
        forms.forEach(form => form.style.display = 'none');
    }

    redirectToDashboard() {
        // Simulación de redirección
        this.showNotification('Redirigiendo al dashboard...', 'info');
        setTimeout(() => {
            window.location.href = '/dashboard';
        }, 1500);
    }

    // ===== API Y COMUNICACIONES =====
    async mockApiCall(endpoint, data) {
        // Simulación de delay de red
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));

        // Simulación de respuestas según el endpoint
        switch (endpoint) {
            case '/auth/login':
                if (data.email === 'demo@bitwallet.com' && data.password === '123456') {
                    return {
                        success: true,
                        token: 'mock_jwt_token_' + Date.now(),
                        user: {
                            id: 1,
                            name: 'Usuario Demo',
                            email: data.email,
                            business: 'Mi Emprendimiento'
                        }
                    };
                } else {
                    return {
                        success: false,
                        message: 'Credenciales incorrectas'
                    };
                }

            case '/auth/register':
                // Simular verificación de email único
                if (data.email === 'existente@bitwallet.com') {
                    return {
                        success: false,
                        message: 'Este email ya está registrado'
                    };
                }

                return {
                    success: true,
                    message: 'Usuario registrado exitosamente'
                };

            default:
                return {
                    success: false,
                    message: 'Endpoint no encontrado'
                };
        }
    }

    setAuthHeader(token) {
        this.authHeader = { 'Authorization': `Bearer ${token}` };
    }

    removeAuthHeader() {
        this.authHeader = null;
    }

    // ===== ANALYTICS Y MONITORING =====
    trackEvent(eventName, properties = {}) {
        // Integración con analytics (Google Analytics, Mixpanel, etc.)
        if (typeof gtag !== 'undefined') {
            gtag('event', eventName, properties);
        }

        // Log interno para debugging
        console.log(`[Analytics] ${eventName}`, properties);
    }

    initializeServiceWorker() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker
                .register('/sw.js')
                .then(registration => {
                    console.log('Service Worker registrado:', registration);
                })
                .catch(error => {
                    console.log('Error registrando Service Worker:', error);
                });
        }
    }

    setupPerformanceMonitoring() {
        // Monitoring de performance
        if ('performance' in window) {
            window.addEventListener('load', () => {
                const navigationTiming = performance.getEntriesByType('navigation')[0];
                const loadTime = navigationTiming.loadEventEnd - navigationTiming.navigationStart;
                
                this.trackEvent('page_load_time', {
                    load_time: loadTime,
                    domain_lookup: navigationTiming.domainLookupEnd - navigationTiming.domainLookupStart,
                    connect_time: navigationTiming.connectEnd - navigationTiming.connectStart
                });
            });
        }
    }

    // ===== UTILIDADES AVANZADAS =====
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    // ===== MANEJO DE ERRORES GLOBAL =====
    setupErrorHandling() {
        window.addEventListener('error', (event) => {
            this.trackEvent('javascript_error', {
                message: event.message,
                filename: event.filename,
                lineno: event.lineno,
                colno: event.colno
            });
        });

        window.addEventListener('unhandledrejection', (event) => {
            this.trackEvent('unhandled_promise_rejection', {
                reason: event.reason?.toString()
            });
        });
    }

    updateUIForAuthenticatedUser() {
        // Actualizar UI cuando el usuario está autenticado
        const authButtons = document.querySelector('.auth-buttons');
        if (authButtons && this.currentUser) {
            authButtons.innerHTML = `
                <span class="user-welcome">Hola, ${this.currentUser.name}</span>
                <button class="btn btn-outline" onclick="bitWalletSystem.logout()">Cerrar Sesión</button>
            `;
        }
    }

    updateUIForUnauthenticatedUser() {
        // Restaurar UI cuando no hay usuario autenticado
        const authButtons = document.querySelector('.auth-buttons');
        if (authButtons) {
            authButtons.innerHTML = `
                <button class="btn btn-outline" onclick="bitWalletSystem.showLogin()">Iniciar Sesión</button>
                <button class="btn btn-primary" onclick="bitWalletSystem.showRegister()">Registrarse</button>
            `;
        }
    }

    logout() {
        this.clearSession();
        this.showNotification('Sesión cerrada correctamente', 'info');
        this.trackEvent('user_logout');
    }
}

// ===== INICIALIZACIÓN DEL SISTEMA =====
const bitWalletSystem = new BitWalletSystem();

// Event Listeners globales
document.addEventListener('DOMContentLoaded', function() {
    // Prevenir envío de formularios por defecto
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', (e) => e.preventDefault());
    });

    // Cerrar modales con ESC
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            bitWalletSystem.hideAuthForms();
        }
    });

    // Manejo de clicks fuera de los modales
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('auth-form-container')) {
            bitWalletSystem.hideAuthForms();
        }
    });

    // Smooth scrolling mejorado
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Performance optimization: Lazy loading de imágenes
    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.remove('lazy');
                    imageObserver.unobserve(img);
                }
            });
        });

        document.querySelectorAll('img[data-src]').forEach(img => {
            imageObserver.observe(img);
        });
    }
});

// Exportar para uso global (si es necesario)
window.BitWalletSystem = BitWalletSystem;
window.bitWalletSystem = bitWalletSystem;