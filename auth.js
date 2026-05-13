// Authentication and User Management Functions

function checkAuth() {
    const isLoggedIn = localStorage.getItem('healthmate_loggedIn');
    const userEmail = localStorage.getItem('healthmate_user');
    const userName = localStorage.getItem('healthmate_userName');
    const userId = localStorage.getItem('healthmate_userId');
    
    if (!isLoggedIn || !userEmail) {
        console.log('❌ User not authenticated, redirecting to login...');
        window.location.href = 'login.html';
        return false;
    }
    
    console.log('✅ User authenticated:', { userId, userName, userEmail });
    
    // Update profile information across the application
    updateUserProfileInfo(userName, userEmail);
    
    return true;
}

function updateUserProfileInfo(userName, userEmail) {
    // Update profile section
    if (document.getElementById('profileName')) {
        document.getElementById('profileName').textContent = userName || userEmail.split('@')[0];
    }
    if (document.getElementById('profileEmail')) {
        document.getElementById('profileEmail').textContent = userEmail;
    }
    
    // Update family section
    if (document.getElementById('userName')) {
        document.getElementById('userName').textContent = (userName || userEmail.split('@')[0]) + ' (You)';
    }
    
    // Update dashboard welcome message if exists
    if (document.getElementById('welcomeMessage')) {
        document.getElementById('welcomeMessage').textContent = `Welcome back, ${userName || userEmail.split('@')[0]}!`;
    }
    
    // Update navigation if exists
    if (document.getElementById('userNavInfo')) {
        document.getElementById('userNavInfo').textContent = userName || userEmail.split('@')[0];
    }
}

function logout() {
    const userEmail = localStorage.getItem('healthmate_user');
    const userName = localStorage.getItem('healthmate_userName');
    
    console.log('🚪 User logging out:', { userEmail, userName });
    
    // Clear all user data from localStorage
    localStorage.removeItem('healthmate_user');
    localStorage.removeItem('healthmate_loggedIn');
    localStorage.removeItem('healthmate_userId');
    localStorage.removeItem('healthmate_userName');
    
    // Optional: Clear any other app-specific data
    localStorage.removeItem('healthmate_userProfile');
    localStorage.removeItem('healthmate_lastActivity');
    
    // Redirect to login page
    window.location.href = 'login.html';
}

// Function to get current user info
function getCurrentUser() {
    return {
        id: localStorage.getItem('healthmate_userId'),
        email: localStorage.getItem('healthmate_user'),
        name: localStorage.getItem('healthmate_userName'),
        isLoggedIn: localStorage.getItem('healthmate_loggedIn') === 'true'
    };
}

// Function to check if user is logged in (without redirect)
function isUserLoggedIn() {
    const isLoggedIn = localStorage.getItem('healthmate_loggedIn');
    const userEmail = localStorage.getItem('healthmate_user');
    return !!(isLoggedIn && userEmail);
}

// Function to update user profile data
async function updateUserProfile(profileData) {
    try {
        const userEmail = localStorage.getItem('healthmate_user');
        
        const response = await fetch(`http://localhost:5000/api/profile/${userEmail}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(profileData)
        });

        const result = await response.json();
        
        if (result.success) {
            console.log('✅ Profile updated successfully:', result.user);
            
            // Update localStorage with new user data if needed
            if (result.user.name) {
                localStorage.setItem('healthmate_userName', result.user.name);
                updateUserProfileInfo(result.user.name, userEmail);
            }
            
            return { success: true, user: result.user };
        } else {
            console.error('❌ Profile update failed:', result.message);
            return { success: false, message: result.message };
        }
    } catch (error) {
        console.error('❌ Network error updating profile:', error);
        return { success: false, message: 'Network error updating profile' };
    }
}

// Function to get user profile from server
async function fetchUserProfile() {
    try {
        const userEmail = localStorage.getItem('healthmate_user');
        
        if (!userEmail) {
            console.error('❌ No user email found in localStorage');
            return null;
        }

        const response = await fetch(`http://localhost:5000/api/profile/${userEmail}`);
        const result = await response.json();
        
        if (result.success) {
            console.log('✅ User profile fetched:', result.user);
            
            // Store additional user data if needed
            localStorage.setItem('healthmate_userProfile', JSON.stringify(result.user));
            
            return result.user;
        } else {
            console.error('❌ Failed to fetch user profile:', result.message);
            return null;
        }
    } catch (error) {
        console.error('❌ Network error fetching profile:', error);
        return null;
    }
}

// Function to validate session on page load
function validateSession() {
    const user = getCurrentUser();
    
    if (!user.isLoggedIn) {
        console.log('❌ No valid session found');
        return false;
    }
    
    // Check if session data is complete
    if (!user.id || !user.email) {
        console.log('❌ Incomplete session data');
        logout();
        return false;
    }
    
    console.log('✅ Session validated:', user);
    return true;
}

// Function to set user activity timestamp
function setUserActivity() {
    localStorage.setItem('healthmate_lastActivity', new Date().toISOString());
}

// Function to check session timeout (optional feature)
function checkSessionTimeout() {
    const lastActivity = localStorage.getItem('healthmate_lastActivity');
    if (!lastActivity) return false;
    
    const lastActivityTime = new Date(lastActivity);
    const currentTime = new Date();
    const timeDiff = (currentTime - lastActivityTime) / (1000 * 60); // difference in minutes
    
    // Auto-logout after 24 hours (1440 minutes)
    if (timeDiff > 1440) {
        console.log('🕒 Session expired due to inactivity');
        logout();
        return true;
    }
    
    return false;
}

// Initialize auth system
function initializeAuth() {
    console.log('🔐 Initializing authentication system...');
    
    // Validate existing session
    if (isUserLoggedIn()) {
        if (!validateSession()) {
            console.log('❌ Session validation failed');
            return false;
        }
        
        // Set initial activity timestamp
        setUserActivity();
        
        // Set up periodic session checking (optional)
        setInterval(() => {
            if (checkSessionTimeout()) {
                alert('Your session has expired due to inactivity. Please login again.');
            }
        }, 60000); // Check every minute
        
        console.log('✅ Auth system initialized successfully');
        return true;
    }
    
    console.log('ℹ️  No active session found');
    return false;
}

// Function to handle protected routes
function requireAuth() {
    if (!checkAuth()) {
        return false;
    }
    
    // Update activity timestamp on page interaction
    setUserActivity();
    return true;
}

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        checkAuth,
        logout,
        getCurrentUser,
        isUserLoggedIn,
        updateUserProfile,
        fetchUserProfile,
        validateSession,
        initializeAuth,
        requireAuth
    };
}

// Global functions for HTML onclick attributes
window.logout = logout;
window.checkAuth = checkAuth;

console.log('✅ auth.js loaded successfully');