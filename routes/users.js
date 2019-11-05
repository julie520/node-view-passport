const router = require('express').Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

// User model
const User = require('../models/User');


/**
 * Route serving login form.
 * @name get/login
 * @function
 * @memberof module:routers/users~usersRouter
 * @inner
 * @param {string} path - Express path
 * @param {callback} middleware - Express middleware.
 */
router.get('/login', (req, res) => res.render('login'));

/**
 * Route serving login form.
 * @name get/register
 * @function
 * @memberof module:routers/users~usersRouter
 * @inner
 * @param {string} path - Express path
 * @param {callback} middleware - Express middleware.
 */
router.get('/register', (req, res) => res.render('register'));

// Register Handle
router.post('/register', async (req, res) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (password != password2) {
    errors.push({ msg: 'Passwords do not match' });
  }

  if (password.length < 6) {
    errors.push({ msg: 'Password must be at least 6 characters' });
  }

  if (errors.length > 0) {
    return res.render('register', {
      errors,
      name,
      email,
      password,
      password2
    });
  }

  // check 
  User.findOne({ email })
    .then(user => {
      if (user) {
        // User exists
        errors.push({ msg: 'Email is already registered' });
        return res.render('register', {
          errors,
          name,
          email,
          password,
          password2
        });
      }

      const newUser = new User({
        name,
        email,
        password
      });

      // Hash Password
      bcrypt.genSalt(10, (err, salt) =>
        bcrypt.hash(password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          newUser.save()
            .then(user => {
              req.flash('success_msg', 'You are now registered and can log in');
              res.redirect('/users/login');
            })
            .catch(err => console.log(err));
      }));
    });
});

// Login Handle
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  })(req,res, next);
});

// Logout Handle
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

module.exports = router;