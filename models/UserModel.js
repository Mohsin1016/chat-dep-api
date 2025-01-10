const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    email: { type: String, required: true, unique: true },

    profileImage: {
      type: String,
      default: "", // This will store the URL of the profile image uploaded to Cloudinary
    },
    isVerified: { type: Boolean, default: false },
  },
  
  { timestamps: true }
);

const UserModel = mongoose.model("User", UserSchema);
module.exports = UserModel;
