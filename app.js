require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const nodemailer = require("nodemailer");
const argon2 = require("argon2");
const User = require("./models/User");
const multer = require("multer");
const crypto = require("crypto");
const { hashPassword } = require("./models/hash");
const generateSessionKey = require("./models/session");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const Donation = require("./models/Donation");
const stripe = require("stripe")(process.env.SECRET_KEY);
const PDFDocument = require("pdfkit");
const fs = require("fs");

let isCorrect = "";

const app = express();
const port = 80;

let sessionKey = generateSessionKey();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const dbUrl = process.env.MONGODB_URI;
const connectionParams = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const store = new MongoDBStore({
  uri: dbUrl,
  collection: "sessions",
});
store.on("error", function (error) {
  console.error("Error connecting to MongoDB session store:", error);
});

app.use(
  session({
    secret: sessionKey,
    resave: false,
    saveUninitialized: true,
    store: store,
    expires: new Date(Date.now() + 60 * 60 * 1000),
  })
);

const checkLoggedIn = (req, res, next) => {
  if (req.session && req.session.userId) {
    res.locals.isLoggedIn = true;
  } else {
    res.locals.isLoggedIn = false;
  }
  next();
};

app.use(checkLoggedIn);

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./others/uploads");
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage: storage });

main().catch((err) => console.log(err));

async function main() {
  await mongoose
    .connect(dbUrl, connectionParams)
    .then(() => {
      console.info("Connected to DB");
    })
    .catch((e) => {
      console.log("error", e);
    });
}
app.listen(port, () => {
  console.log(`Listening on PORT: ${port}`);
});

const contactschema = new mongoose.Schema({
  Name: String,
  Phone: Number,
  Email: String,
  State: String,
  Message: String,
});

const emailschema = new mongoose.Schema({
  Email: String,
});

const donategoodsschema = new mongoose.Schema({
  Name: String,
  Address: String,
  Options: String,
  image: String,
  Goodsdonatedate: {
    type: Date,
  },
});

const email = mongoose.model("Email", emailschema);
const contact = mongoose.model("Contact", contactschema);
const donategoods = mongoose.model("goodsdonors", donategoodsschema);

const isAdminAuthenticated = (req, res, next) => {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  res.redirect("/login");
  isCorrect = "Please login as Admin!";
};

const generateNumericOTP = () => {
  const otpLength = 6;
  let otp = "";
  for (let i = 0; i < otpLength; i++) {
    otp += crypto.randomInt(10);
  }
  return otp;
};

function generateReceipt(Name, Amount, Purpose, paymentId) {
  const doc = new PDFDocument();
  const receiptFileName = `receipt_${Date.now()}.pdf`;
  const receiptPath = __dirname + "/receipts/" + receiptFileName;
  const stream = fs.createWriteStream(receiptPath);

  doc.pipe(stream);
  doc.fontSize(18).text("Receipt", { align: "center" });
  doc.fontSize(14).text(`Name: ${Name}`);
  doc.fontSize(14).text(`Amount: ${Amount}`);
  doc.fontSize(14).text(`Purpose: ${Purpose}`);
  doc.fontSize(14).text(`Payment Id: ${paymentId}`);

  doc.end();

  return receiptFileName;
}

let transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: "donatedotin@gmail.com",
    pass: process.env.pass,
  },
});

app.use(express.static(path.join(__dirname, "./others")));

app.use(express.urlencoded({ extended: true }));

//GET ROUTES

app.get("/", async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalDonationResult = await Donation.aggregate([
      {
        $group: {
          _id: null,
          totalDonation: { $sum: "$Amount" },
        },
      },
    ]);
    const totalDonation = totalDonationResult[0]?.totalDonation || 0;
    res.render("index", {
      isLoggedIn: res.locals.isLoggedIn,
      displayUser: req.session.Name || "",
      totalUsers,
      totalDonation,
    });
  } catch (err) {
    console.error("Error counting total users:", err);
    res.status(500).send("Error counting total users.");
  }
});

app.get("/index", (req, res) => {
  res.render("index", { displayUser: req.session.Name });
});

app.get("/contact", (req, res) => {
  res.render("contact", { displayUser: req.session.Name || "" });
});

app.get("/donate", (req, res) => {
  if (res.locals.isLoggedIn) {
    res.render("donate", { displayUser: req.session.Name || "" });
  } else {
    res.redirect("login");
  }
});

app.get("/about", (req, res) => {
  res.render("about", { displayUser: req.session.Name || "" });
});

app.get("/login", (req, res) => {
  res.render("login", { isCorrect: isCorrect, displayUser: "displayUser" });
  isCorrect = "";
});
app.get("/SignUp", (req, res) => {
  res.render("registration", { isCorrect: isCorrect });
  isCorrect = "";
});

app.get("/forgotPassword", (req, res) => {
  res.render("forgotPassword", { isCorrect: isCorrect });
  isCorrect = "";
});

app.get("/resetPassword", async (req, res) => {
  var Username = req.query.Username;
  var resetToken = req.query.resetToken;
  try {
    var user = await User.findOne({ Username, resetToken });
    if (user.resetTokenExpiration < Date.now()) {
      return res.status(404).send("Reset Link has been expired");
    }
  } catch (err) {
    return res.status(400).send("Your link has been expired");
  }
  res.render("resetPassword", { isCorrect: isCorrect, resetToken, Username });
  isCorrect = "";
});

app.get("/logout", (req, res) => {
  req.session.Name = null;
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    }
    res.redirect("/");
  });
});

app.get("/admin/dashboard", isAdminAuthenticated, async (req, res) => {
  try {
    const donationData = await Donation.aggregate([
      {
        $group: {
          _id: "$Moneydonatedate",
          totalDonation: { $sum: "$Amount" },
        },
      },
      {
        $sort: { _id: 1 },
      },
    ]);

    let h;
    donationData.forEach((item) => {
      h = new Date(item._id);
      item._id = h.toLocaleDateString("en-IN", { timeZone: "Asia/Kolkata" });
    });

    const dates = [];
    const totals = [];
    let currentDate = donationData[0]._id;
    let currentTotal = 0;

    donationData.forEach((item) => {
      if (item._id === currentDate) {
        currentTotal += item.totalDonation;
      } else {
        dates.push(currentDate);
        totals.push(currentTotal);
        currentDate = item._id;
        currentTotal = item.totalDonation;
      }
    });

    dates.push(currentDate);
    totals.push(currentTotal);

    const totalUsers = await User.countDocuments();
    const totalDonationResult = await Donation.aggregate([
      {
        $group: {
          _id: null,
          totalDonation: { $sum: "$Amount" },
        },
      },
    ]);
    const totalDonation = totalDonationResult[0]?.totalDonation || 0;
    res.render("./admin/dashboard", {
      displayUser: req.session.Name || "",
      totalUsers,
      totalDonation,
      donationData: {
        totals,
        dates,
      },
    });
  } catch (error) {
    res.status(500).send("Internal server error");
  }
});

app.get("/admin/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying admin session:", err);
    }
    res.redirect("/login");
  });
});

app.get("/admin/users", isAdminAuthenticated, async (req, res) => {
  try {
    const users = await User.find();
    res.render("admin/users", { users, displayUser: req.session.Name || "" });
  } catch (err) {
    res.status(500).send("Internal server error");
  }
});

app.get("/admin/donations", isAdminAuthenticated, async (req, res) => {
  try {
    const users = await Donation.find();
    const goods = await donategoods.find();
    res.render("admin/donations", {
      goods,
      users,
      displayUser: req.session.Name || "",
    });
  } catch (err) {
    res.status(500).send("Internal server error");
  }
});

app.get(
  "/admin/dashboard/:selectedDate",
  isAdminAuthenticated,
  async (req, res) => {
    try {
      let selectedDate = new Date(req.params.selectedDate);
      selectedDate = selectedDate.toLocaleDateString("en-IN", {
        timeZone: "Asia/Kolkata",
      });
      const donationData = await Donation.aggregate([
        {
          $group: {
            _id: "$Moneydonatedate",
            totalDonation: { $sum: "$Amount" },
          },
        },
        {
          $sort: { _id: 1 },
        },
      ]);

      let h;
      donationData.forEach((item) => {
        h = new Date(item._id);
        item._id = h.toLocaleDateString("en-IN", { timeZone: "Asia/Kolkata" });
      });

      const dates = [];
      const totals = [];
      let currentDate = donationData[0]._id;
      let currentTotal = 0;

      donationData.forEach((item) => {
        if (item._id === currentDate) {
          currentTotal += item.totalDonation;
        } else {
          dates.push(currentDate);
          totals.push(currentTotal);
          currentDate = item._id;
          currentTotal = item.totalDonation;
        }
      });

      dates.push(currentDate);
      totals.push(currentTotal);
      let totalDonationForDate = 0;
      let i;
      for (i = 0; i < dates.length; i++) {
        if (dates[i] == selectedDate) {
          totalDonationForDate = totals[i];
          break;
        }
      }
      const data = {
        dates: [selectedDate],
        totals: [totalDonationForDate],
      };

      res.json(data);
    } catch (error) {
      res.status(500).send("Internal server error");
    }
  }
);

app.get("/download-receipt/:filename", (req, res) => {
  const filename = req.params.filename;
  const filePath = __dirname + "/receipts/" + filename;

  res.download(filePath, "receipt.pdf", (err) => {
    if (err) {
      console.error("Error sending receipt:", err);
    } else {
      fs.unlinkSync(filePath);
    }
  });
});

//POST ROUTES

app.post("/admin/updateUserAdminStatus", async (req, res) => {
  const Email = req.body.Email;
  const newAdminStatus = req.body.isAdmin;

  try {
    const user = await User.findOne({ Email });
    if (!user) {
      return res.status(404).send("User not found.");
    }
    if (newAdminStatus === "on") user.isAdmin = true;
    else user.isAdmin = false;

    await user.save();

    res.redirect("/admin/users");
  } catch (err) {
    return res.status(500).send("Internal server error");
  }
});

app.post("/admin/deleteUser", async (req, res) => {
  const Email = req.body.Email;

  try {
    const user = await User.findOneAndDelete({ Email });
    if (!user) {
      return res.status(404).send("User not found.");
    }

    res.redirect("/admin/users");
  } catch (err) {
    res.status(500).send("Internal server error");
  }
});

app.post("/contact", (req, res) => {
  var tempdata = new contact(req.body);
  tempdata
    .save()
    .then(() => {
      transporter.sendMail({
        from: "donatedotin@gmail.com",
        to: req.body.Email,
        subject: "Apreciation",
        text: "Thank you for joining our organization. We will contact you soon..",
      });
      res.status(204).send();
    })
    .catch(() => {
      res
        .status(400)
        .send("Your contact information is not being stored due to an error");
    });
});

app.post("/emailsub", (req, res) => {
  var tempdata = new email(req.body);
  tempdata
    .save()
    .then(() => {
      transporter.sendMail({
        from: "donatedotin@gmail.com",
        to: req.body.Email,
        subject: "Apreciation",
        text: "Thank you for joining our organization.",
      });
      res.status(204).send();
    })
    .catch(() => {
      res
        .status(400)
        .send("Your contact information is not being stored due to an error");
    });
});

app.post("/donatemoney", (req, res) => {
  const Moneydonatedate = new Date();
  const { Name, Phone, Amount, Purpose, paymentId } = req.body;
  try {
    var tempdata = new Donation({
      Name,
      Phone,
      Amount,
      Purpose,
      Moneydonatedate,
    });
    tempdata.save().then(() => {
      const receiptFileName = generateReceipt(Name, Amount, Purpose, paymentId);
      const receiptLink = `/download-receipt/${receiptFileName}`;

      res.json({ success: true, receiptLink });
    });
  } catch (error) {
    res
      .status(400)
      .send("Your contact information is not being stored due to an error");
  }
});

app.post("/donategoods", upload.single("Images"), (req, res) => {
  const Goodsdonatedate = new Date();
  const { Name, Address, Options } = req.body;
  const image = req.file.originalname;
  var tempdata = new donategoods({
    Name,
    Address,
    Options,
    image,
    Goodsdonatedate,
  });
  tempdata
    .save()
    .then(() => {
      res.status(204).send();
    })
    .catch(() => {
      res
        .status(400)
        .send("Your contact information is not being stored due to an error");
    });
});

app.post("/registration", async (req, res) => {
  var { Name, Username, Email, Password } = req.body;
  try {
    if (await User.findOne({ Username })) {
      return res.render("registration", {
        isCorrect: "Username already exists!",
      });
    }
    if (await User.findOne({ Email })) {
      return res.render("registration", { isCorrect: "Email already exists!" });
    }

    const otp = generateNumericOTP();
    var tempdata = new User({
      Name,
      Username,
      Email,
      Password,
      otp: otp,
      otpExpiration: Date.now() + 5 * 60 * 1000,
    });

    tempdata.save().then(() => {
      transporter.sendMail({
        from: "donationdootin@gmail.com",
        to: req.body.Email,
        subject: "Email Verification OTP",
        text: `Your Email Verification OTP is ${otp}`,
      });
      res.send("Registration successful");
    });
  } catch (err) {
    console.error("Error registering user:", err);
    return res.send("Error registering user.");
  }
});

app.post("/confirmEmail", async (req, res) => {
  const { Email, otp } = req.body;
  const user = await User.findOne({ Email });
  if (!user) {
    return res.render("registration", { isCorrect: "Incorrect OTP entered." });
  }
  try {
    if (user.otp != otp)
      return res.render("registration", {
        isCorrect: "Incorrect OTP entered.",
      });
    user.isVerified = true;
    user.otp = undefined;
    user.otpExpiration = undefined;
    await user.save();
    transporter.sendMail({
      from: "donatedotin@gmail.com",
      to: Email,
      subject: "Registration Successful",
      text: "Thank you for joining our organization. You are successfully registered...",
    });
    res.render("registration", { isCorrect: "Registration successful!!" });
  } catch (err) {
    res.send("Their was an Error in Confirming").status(500);
  }
});

app.post("/login", async (req, res) => {
  var { Username, Password, userType } = req.body;

  try {
    const isEmail = /\S+@\S+\.\S+/.test(Username);
    const searchCriteria = isEmail
      ? { Email: Username }
      : { Username: Username };
    var user = await User.findOne(searchCriteria);

    if (!user) {
      isCorrect = "Incorrect Email or Username";
      return res.redirect("/login");
    }
    if (!user.isVerified) {
      isCorrect = "Verify your Email first!!!";
      return res.redirect("/login");
    }
    const passwordMatch = await argon2.verify(user.Password, Password);
    if (passwordMatch) {
      const userTypedb = user.isAdmin ? "admin" : "user";
      if (userType === userTypedb) {
        isCorrect = "";
        req.session.userId = user._id;
        req.session.Name = user.Name.split(" ")[0];
        req.session.isAdmin = user.isAdmin;
        sessionKey = generateSessionKey();
        req.session.secret = sessionKey;
        if (userType === "user") {
          return res.redirect("/donate");
        } else {
          return res.redirect("/admin/dashboard");
        }
      } else {
        isCorrect = "Check your user type !!!";
        return res.redirect("/login");
      }
    } else {
      isCorrect = "Incorrect Password";
      return res.redirect("/login");
    }
  } catch (err) {
    console.error("Error finding user:", err);
    return res.send("Error finding user.");
  }
});

app.post("/forgotPassword", async (req, res) => {
  var { Email } = req.body;

  try {
    var user = await User.findOne({ Email });

    if (!user) {
      return res.render("forgotPassword", { isCorrect: "User not found." });
    }

    var resetToken = crypto.randomBytes(32).toString("hex");
    user.resetToken = resetToken;
    user.resetTokenExpiration = Date.now() + 2 * 60 * 1000; // 2 minutes

    await user.save();

    var transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: "donatedotin@gmail.com",
        pass: "ithbqccopwzpnzqu",
      },
    });

    var mailOptions = {
      from: "donatedotin@gmail.com",
      to: user.Email,
      subject: "Password Reset",
      html: `
          <p>You requested a Password reset.</p>
          <p>Click this <a href="https://donation-in.onrender.com/resetPassword?resetToken=${resetToken}&Username=${user.Username}">link</a> to reset your Password.</p>
        `,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(400).send("Error sending email.");
      }
      res.render("forgotPassword", {
        isCorrect: "Password reset email sent successfully.",
      });
    });
  } catch (err) {
    console.error("Error sending reset token:", err);
    res.status(500).send("Error sending reset token.");
  }
});

app.post("/resetPassword", async (req, res) => {
  var { Username, Password } = req.body;
  try {
    var user = await User.findOne({ Username });

    if (!user) {
      return res.status(404).send("User not found");
    }
    if (user.resetTokenExpiration < Date.now()) {
      return res.status(404).send("Reset Link has been expired");
    }

    var hashedPassword = Password;
    user.Password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;

    await user.save();

    isCorrect = "Password reset successfully!!!";
    return res.redirect("/login");
  } catch (err) {
    console.error("Error resetting Password:", err);
    res.status(500).send("Error resetting Password.");
  }
});

app.post("/create-payment-intent", async (req, res) => {
  try {
    const { Amount } = req.body;
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Amount * 100,
      currency: "inr",
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      paymentId: paymentIntent.id,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Something went wrong" });
  }
});
