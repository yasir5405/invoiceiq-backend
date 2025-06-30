import mongoose from "mongoose";

const Schema = mongoose.Schema;

const ObjectId = Schema.ObjectId;

const userSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: false,
    },
    profileImage: {
      type: String,
      required: false,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    googleId: { type: String, required: false, unique: true },
  },
  { timestamps: true }
);

const UserModel = mongoose.model("users", userSchema);

export { UserModel };
