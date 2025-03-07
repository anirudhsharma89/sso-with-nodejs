const express = require('express');
const passport = require('passport');
const session = require('express-session');
const SamlStrategy = require('passport-saml').Strategy;
const fs = require('fs');
require('dotenv').config();

const app = express();

// Middleware to parse request bodies
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Session management
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(new SamlStrategy(
  {
      path: 'http://localhost:3000/login/callback',  // Callback URL after SAML authentication
      entryPoint: process.env.ENTRY_POINT, // Identity Provider SSO URL
      issuer: 'http://localhost:3000', // Entity ID of your app
      cert: process.env.SAML_CERT,  // Public Certificate of your IdP
  },
  (profile, done) => {
      // Map SAML response attributes to user object
      console.log(profile);
      return done(null, {
          id: profile.nameID,
          email: profile['email'],
          displayName: profile['displayName']
      });
  }
));

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Login Route - Redirects to SAML Identity Provider
app.get('/login', passport.authenticate('saml'));

// Callback Route - Handles SAML Response
app.post('/login/callback',
    passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
    (req, res) => {
        res.redirect('/dashboard');
    }
);

// Protected Route - Only for authenticated users
app.get('/dashboard', (req, res) => {    
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    res.send(`Welcome ${req.user.id}`);
});

// Logout Route
app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/');
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
