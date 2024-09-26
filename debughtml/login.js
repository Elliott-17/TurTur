// Import Firebase modules
import { initializeApp } from 'https://www.gstatic.com/firebasejs/9.0.0/firebase-app.js';
import { getAuth, GoogleAuthProvider, signInWithPopup, signInWithEmailAndPassword, createUserWithEmailAndPassword, sendPasswordResetEmail } from 'https://www.gstatic.com/firebasejs/9.0.0/firebase-auth.js';

// Your Firebase configuration
const firebaseConfig = {
apiKey: "AIzaSyDbqo9t-JfnzDxHAP6z1CQzJXYXdYBzOlE",
authDomain: "turtur-aa8f8.firebaseapp.com",
projectId: "turtur-aa8f8",
storageBucket: "turtur-aa8f8.appspot.com",
messagingSenderId: "60240798269",
appId: "1:60240798269:web:4fcb192af720da39f14054"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const provider = new GoogleAuthProvider();

// Function to sign in with Google
document.getElementById('login-button-google1').addEventListener('click', () => {
    doGoogleLogin();
});

document.getElementById('login-button-google2').addEventListener('click', () => {
    doGoogleLogin();
});

function doGoogleLogin() {
    signInWithPopup(auth, provider)
        .then((result) => {
            // Get the ID token
            result.user.getIdToken().then((idToken) => {
                signInWithIdToken(idToken);
            });
        })
        .catch((error) => {
            console.error('Error signing in:', error);
            alert('Error signing in with Google. Please try again.');
        });
}

// Function to sign in with email and password
document.getElementById('login-with-email').addEventListener('click', (event) => {
    event.preventDefault();
    const email = document.getElementById('email_login').value;
    const password = document.getElementById('password_login').value;

    signInWithEmailAndPassword(auth, email, password)
        .then((userCredential) => {
            // Signed in
            const user = userCredential.user;
            console.log('User:', user);
            // Get the ID token
            user.getIdToken().then((idToken) => {
                signInWithIdToken(idToken);
            });
        })
        .catch((error) => {
            console.error('Error signing in:', error);
            // Extract error message
            const errorCode = error.code;
            const errorMessage = error.message;
            // Check for specific error codes from firebase auth
            if (errorCode === 'auth/invalid-login-credentials') {
                alert('Invalid Login Credentials. Please try again.');
            } else {
                alert("Error signing in. Please try again.");
            }
        });
});

// Function to sign up with email and password
document.getElementById('signup-with-email').addEventListener('click', (event) => {
    // ensure both passwords match
    if (document.getElementById('password_signup').value !== document.getElementById('confirm_password').value) {
        alert('Passwords do not match');
        return;
    }
    event.preventDefault();
    const email = document.getElementById('email_signup').value;
    const password = document.getElementById('password_signup').value;

    createUserWithEmailAndPassword(auth, email, password)
        .then((userCredential) => {
            // Signed in
            const user = userCredential.user;
            console.log('User:', user);
            user.getIdToken().then((idToken) => {
                signInWithIdToken(idToken);
            });
        })
        .catch((error) => {
            console.error('Error signing up:', error);
            alert('Error signing up. Please try again.');
        });
});

// Function to request password reset
document.getElementById('reset-password').addEventListener('click', (event) => {
    event.preventDefault();

    const email = document.getElementById('email_reset').value;
    sendPasswordResetEmail(auth, email)
        .then(() => {
            console.log('Password reset email sent');
            alert('Password reset email sent');
        })
        .catch((error) => {
            console.error('Error sending password reset email:', error);
        });
});

// Function to sign in with ID token once received
function signInWithIdToken(idToken) {

    fetch('/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ id_token: idToken }),
                })
                .then(response => response.json())
                .then(
                    data => {
                        document.cookie = `session_id=${data.session_id}`;
                        sessionStorage.setItem('user_id', data.user_id);
                        sessionStorage.setItem('encryption_key', data.encryption_key);

                        window.location.href = '/app';
                    }
                )
                .catch(error => {
                    console.error('Error:', error)
                    alert('Error signing in. You may not have access to this application. Please contact the administrator.');
                    window.location.reload();
                });
}


// Page changing
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('login-button-1').addEventListener('click', function() {
        document.getElementById('login-form').classList.remove('hide');
        document.getElementById('login-form').classList.add('show');
        document.getElementById('signup-form').classList.remove('show');
        document.getElementById('signup-form').classList.add('hide');
        document.getElementById('reset-password-form').classList.remove('show');
        document.getElementById('reset-password-form').classList.add('hide');
    });

    document.getElementById('login-button-2').addEventListener('click', function() {
        document.getElementById('login-form').classList.remove('hide');
        document.getElementById('login-form').classList.add('show');
        document.getElementById('signup-form').classList.remove('show');
        document.getElementById('signup-form').classList.add('hide');
        document.getElementById('reset-password-form').classList.remove('show');
        document.getElementById('reset-password-form').classList.add('hide');
    });

    document.getElementById('signup-button').addEventListener('click', function() {
        document.getElementById('login-form').classList.remove('show');
        document.getElementById('login-form').classList.add('hide');
        document.getElementById('signup-form').classList.remove('hide');
        document.getElementById('signup-form').classList.add('show');
        document.getElementById('reset-password-form').classList.remove('show');
        document.getElementById('reset-password-form').classList.add('hide');
    });

    document.getElementById('reset-password-email').addEventListener('click', function() {
        document.getElementById('login-form').classList.remove('show');
        document.getElementById('login-form').classList.add('hide');
        document.getElementById('signup-form').classList.remove('show');
        document.getElementById('signup-form').classList.add('hide');
        document.getElementById('reset-password-form').classList.remove('hide');
        document.getElementById('reset-password-form').classList.add('show');
    });
});

