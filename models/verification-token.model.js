import mongoose from "mongoose";

const Schema = mongoose.Schema;

const ObjectId = Schema.ObjectId;

const verificationTokenSchema = new Schema(
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

const verificationTokenModel = mongoose.model(
  "verification-token",
  verificationTokenSchema
);

export { verificationTokenModel };
