import mongoose from "mongoose";
const connectDB = async () => {
  await mongoose
    .connect(process.env.MONGO_CONNECTION_URI)
    .then(() => {
      console.log("Database connected");
    })
    .catch(() => {
      console.log("Error connecting to database");
    });
};

export { connectDB };
