const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrpyt = require('bcrypt');

// Define our model
const userSchema  = new Schema({
  email: {
    type: String, 
    unique: true,
    lowercase: true
  },
  password: String 
});

// onSave Hook, encrypt password
// Before saving a model, run this function 
userSchema.pre('save', function(next) {

  // get access to the user model 
  const user = this; // user.email
  console.log(user);

  // generate a salt then run callback 
  bcrpyt.genSalt(10, function(err, salt) {
    if (err) { 
      console.log(err);
      return next(err) 
    };
    
    // hash   
    bcrpyt.hash(user.password, salt, function(err, hash) {
      console.log(err);
      if (err) { return next(err) };
      // overwrite plain text password with encrypted password
      user.password = hash;
      console.log(user);
      next();
    });
  });
}); 

userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrpyt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) { return callback(err) };

    callback(null, isMatch);
  });
};

// Create the model class
const ModelClass = mongoose.model('user', userSchema);

// Export the model
module.exports = ModelClass;
