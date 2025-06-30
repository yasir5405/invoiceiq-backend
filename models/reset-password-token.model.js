import mongoose from "mongoose";

const Schema = mongoose.Schema;

const ObjectId = Schema.ObjectId;

const resetPasswordTokenSchema = new Schema(
  {
    token: {
      type: String,
      required: true,
    },
    userId: {
      type: ObjectId,
      ref: "users",
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 },
    },
  },
  { timestamps: true }
);

const resetPasswordTokenModel = mongoose.model(
  "reset-password-token",
  resetPasswordTokenSchema
);

export { resetPasswordTokenModel };
