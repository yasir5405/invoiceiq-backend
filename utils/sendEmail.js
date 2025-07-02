import nodemailer from "nodemailer";

const sendVerificationEmail = async (email, token) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const link = `https://invoiceiq.xyz/login?token=${token}`;

  await transporter.sendMail({
    from: `InvoiceIQ <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Verify your InvoiceIQ account.",
    html: `<h2>Welcome to Blogwala!</h2>
           <p>Please click the link below to verify your email:</p>
           <a href="${link}">${link}</a>`,
  });
};

const resetPasswordLink = async (email, token) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  // const link = `http://localhost:3000/api/auth/reset-password?token=${token}`;
  const link = `https://www.invoiceiq.xyz/reset-password?token=${token}`;

  await transporter.sendMail({
    from: `InvoiceIQ <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Reset your password for InvoiceIQ account.",
    html: `<h2>Reset your password for InvoiceIQ account.</h2>
           <p>Please click the link below to reset your password:</p>
           <a href="${link}">${link}</a>`,
  });
};

export { sendVerificationEmail, resetPasswordLink };
