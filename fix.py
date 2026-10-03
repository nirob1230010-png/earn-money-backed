code = r'''const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(cors());
app.set("trust proxy", 1);
app.use("/api", rateLimit({ windowMs: 60000, max: 200, validate: { trustProxy: false } }));

mongoose.connect(process.env.MONGO_URI).then(() => console.log("MongoDB connected")).catch(e => console.log("Mongo error:", e.message));

const User = mongoose.model("User", new mongoose.Schema({
  phone: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  deviceId: { type: String, unique: true, required: true },
  name: String, pendingPoints: { type: Number, default: 0 },
  balance: { type: Number, default: 0 }, totalEarned: { type: Number, default: 0 },
  isBanned: { type: Boolean, default: false }, referralCode: { type: String, unique: true },
  referredBy: String, hasCompletedTask: { type: Boolean, default: false },
  referralBonusPaid: { type: Boolean, default: false },
  lastLoginBonus: { type: Date, default: null }, todayTaskCount: { type: Number, default: 0 },
  lastTaskDate: { type: String, default: "" }, weekTaskCount: { type: Number, default: 0 },
  lastWeekReset: { type: String, default: "" }, streakBonusPaid: { type: Boolean, default: false },
  weeklyBonusPaid: { type: Boolean, default: false }, referredCount: { type: Number, default: 0 },
}, { timestamps: true }));

const Task = mongoose.model("Task", new mongoose.Schema({
  title: String, description: String, depositAmt: Number, rewardAmt: Number,
  link: String, logo: String, category: { type: String, default: "betting" },
  isActive: { type: Boolean, default: true }, completed: { type: Number, default: 0 },
}, { timestamps: true }));

const Submission = mongoose.model("Submission", new mongoose.Schema({
  phone: String, taskId: mongoose.Schema.Types.ObjectId, taskTitle: String,
  siteUsername: String, transactionId: String, screenshotUrl: String,
  rewardAmt: Number, status: { type: String, enum: ["PENDING","APPROVED","REJECTED"], default: "PENDING" },
  rejectReason: String,
}, { timestamps: true }));

const Withdrawal = mongoose.model("Withdrawal", new mongoose.Schema({
  phone: String, amount: Number, paymentMethod: String, accountNumber: String,
  status: { type: String, enum: ["PENDING","APPROVED","REJECTED"], default: "PENDING" },
  rejectReason: String,
}, { timestamps: true }));

const Notice = mongoose.model("Notice", new mongoose.Schema({
  title: String, body: String, isActive: { type: Boolean, default: true }
}, { timestamps: true }));

const auth = (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
};

const adminAuth = (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
  try { const d = jwt.verify(token, process.env.JWT_SECRET); if (d.role !== "admin") throw new Error(); next(); }
  catch { res.status(403).json({ error: "Admin only" }); }
};

const WELCOME_BONUS = 50, MIN_WITHDRAW = 100, REFERRAL_BONUS = 25, USD_TO_BDT = 110, USER_REWARD_PERCENT = 50;
const BONUS = { DAILY_LOGIN: 5, TASK_STREAK: 20, WEEKLY: 100, REFER_3: 75 };
function getDateStr() { return new Date().toISOString().slice(0, 10); }
function getWeekStr() { const d = new Date(); const y = d.getFullYear(); const w = Math.ceil(((d - new Date(y, 0, 1)) / 86400000 + 1) / 7); return y + "-W" + w; }

app.post("/api/register", async (req, res) => {
  try {
    const { phone, password, deviceId, name, referralCode } = req.body;
    if (!phone || !password || !deviceId) return res.status(400).json({ error: "Missing fields" });
    if (await User.findOne({ deviceId })) return res.status(400).json({ error: "One device one account" });
    if (await User.findOne({ phone })) return res.status(400).json({ error: "Account exists" });
    const hash = await bcrypt.hash(password, 10);
    const myCode = "EM" + Math.random().toString(36).slice(2, 8).toUpperCase();
    const user = await User.create({ phone, password: hash, deviceId, name, referralCode: myCode, referredBy: referralCode, balance: WELCOME_BONUS, totalEarned: WELCOME_BONUS });
    const token = jwt.sign({ id: user._id, phone, role: "user" }, process.env.JWT_SECRET, { expiresIn: "30d" });
    res.json({ message: "Success", token, user: { phone, name, balance: WELCOME_BONUS, pendingPoints: 0, referralCode: myCode } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/login", async (req, res) => {
  const { phone, password, deviceId } = req.body;
  const user = await User.findOne({ phone });
  if (!user) return res.status(400).json({ error: "No user" });
  if (user.isBanned) return res.status(403).json({ error: "Banned" });
  if (deviceId && user.deviceId !== deviceId) return res.status(403).json({ error: "Wrong device" });
  if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ error: "Wrong pass" });
  const token = jwt.sign({ id: user._id, phone, role: "user" }, process.env.JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { phone, name: user.name, balance: user.balance, pendingPoints: user.pendingPoints, referralCode: user.referralCode } });
});

app.get("/api/me", auth, async (req, res) => { res.json(await User.findOne({ phone: req.user.phone }).select("-password")); });
app.get("/api/tasks", auth, async (req, res) => { const tasks = await Task.find({ isActive: true }).sort({ createdAt: -1 }); const mySubs = await Submission.find({ phone: req.user.phone }).select("taskId status"); res.json({ tasks, mySubs }); });
app.post("/api/submit-task", auth, async (req, res) => {
  const { taskId, siteUsername, transactionId, screenshotUrl } = req.body;
  const task = await Task.findById(taskId);
  if (!task) return res.status(404).json({ error: "No task" });
  const dup = await Submission.findOne({ phone: req.user.phone, taskId, status: { $ne: "REJECTED" } });
  if (dup) return res.status(400).json({ error: "Already" });
  const sub = await Submission.create({ phone: req.user.phone, taskId, taskTitle: task.title, siteUsername, transactionId, screenshotUrl, rewardAmt: task.rewardAmt });
  await User.updateOne({ phone: req.user.phone }, { $inc: { pendingPoints: task.rewardAmt } });
  await Task.updateOne({ _id: task._id }, { $inc: { completed: 1 } });
  res.json({ message: "OK", sub });
});
app.get("/api/my-submissions", auth, async (req, res) => { res.json(await Submission.find({ phone: req.user.phone }).sort({ createdAt: -1 })); });
app.post("/api/withdraw", auth, async (req, res) => {
  const { amount, paymentMethod, accountNumber } = req.body;
  const user = await User.findOne({ phone: req.user.phone });
  if (amount < MIN_WITHDRAW) return res.status(400).json({ error: "Min 100" });
  if (user.balance < amount) return res.status(400).json({ error: "Low" });
  await User.updateOne({ phone: user.phone }, { $inc: { balance: -amount } });
  const w = await Withdrawal.create({ phone: user.phone, amount, paymentMethod, accountNumber });
  res.json({ message: "OK", w });
});
app.get("/api/my-withdrawals", auth, async (req, res) => { res.json(await Withdrawal.find({ phone: req.user.phone }).sort({ createdAt: -1 })); });
app.get("/api/notices", auth, async (req, res) => { res.json(await Notice.find({ isActive: true }).sort({ createdAt: -1 })); });
app.get("/api/config", (req, res) => { res.json({ welcomeBonus: WELCOME_BONUS, minWithdraw: MIN_WITHDRAW, referralBonus: REFERRAL_BONUS, bonus: BONUS }); });

app.post("/api/bonus/daily-login", auth, async (req, res) => {
  const user = await User.findOne({ phone: req.user.phone });
  const today = getDateStr();
  const lastLogin = user.lastLoginBonus ? user.lastLoginBonus.toISOString().slice(0, 10) : null;
  if (lastLogin === today) return res.status(400).json({ error: "Already" });
  await User.updateOne({ _id: user._id }, { $inc: { balance: BONUS.DAILY_LOGIN, totalEarned: BONUS.DAILY_LOGIN }, $set: { lastLoginBonus: new Date() } });
  res.json({ message: "OK", amount: BONUS.DAILY_LOGIN });
});

app.get("/api/bonus/status", auth, async (req, res) => {
  const user = await User.findOne({ phone: req.user.phone });
  const today = getDateStr(); const week = getWeekStr();
  const lastLogin = user.lastLoginBonus ? user.lastLoginBonus.toISOString().slice(0, 10) : null;
  const todayTasks = user.lastTaskDate === today ? user.todayTaskCount : 0;
  const weekTasks = user.lastWeekReset === week ? user.weekTaskCount : 0;
  res.json({
    dailyLogin: { canClaim: lastLogin !== today, amount: BONUS.DAILY_LOGIN },
    taskStreak: { canClaim: todayTasks >= 5 && !user.streakBonusPaid, amount: BONUS.TASK_STREAK, todayTasks, required: 5 },
    weekly: { canClaim: weekTasks >= 50 && !user.weeklyBonusPaid, amount: BONUS.WEEKLY, weekTasks, required: 50 },
    referral3: { canClaim: user.referredCount >= 3 && !user.referralBonusPaid, amount: BONUS.REFER_3, referredCount: user.referredCount, required: 3 },
  });
});

app.post("/api/bonus/task-streak", auth, async (req, res) => {
  const user = await User.findOne({ phone: req.user.phone });
  const today = getDateStr();
  const todayTasks = user.lastTaskDate === today ? user.todayTaskCount : 0;
  if (todayTasks < 5) return res.status(400).json({ error: "Need 5" });
  if (user.streakBonusPaid) return res.status(400).json({ error: "Already" });
  await User.updateOne({ _id: user._id }, { $inc: { balance: BONUS.TASK_STREAK, totalEarned: BONUS.TASK_STREAK }, $set: { streakBonusPaid: true } });
  res.json({ message: "OK", amount: BONUS.TASK_STREAK });
});

app.post("/api/bonus/weekly", auth, async (req, res) => {
  const user = await User.findOne({ phone: req.user.phone });
  const week = getWeekStr();
  const weekTasks = user.lastWeekReset === week ? user.weekTaskCount : 0;
  if (weekTasks < 50) return res.status(400).json({ error: "Need 50" });
  if (user.weeklyBonusPaid) return res.status(400).json({ error: "Already" });
  await User.updateOne({ _id: user._id }, { $inc: { balance: BONUS.WEEKLY, totalEarned: BONUS.WEEKLY }, $set: { weeklyBonusPaid: true } });
  res.json({ message: "OK", amount: BONUS.WEEKLY });
});

app.post("/api/bonus/refer-3", auth, async (req, res) => {
  const user = await User.findOne({ phone: req.user.phone });
  if (user.referredCount < 3) return res.status(400).json({ error: "Need 3" });
  if (user.referralBonusPaid) return res.status(400).json({ error: "Already" });
  await User.updateOne({ _id: user._id }, { $inc: { balance: BONUS.REFER_3, totalEarned: BONUS.REFER_3 }, $set: { referralBonusPaid: true } });
  res.json({ message: "OK", amount: BONUS.REFER_3 });
});

async function processReward(user_id, amount_usd, trans_id, source) {
  const existing = await Submission.findOne({ transactionId: trans_id });
  if (existing) return { status: "OK", msg: "Dup" };
  const user = await User.findOne({ phone: user_id });
  if (!user) return { status: "NOT_FOUND" };
  if (user.isBanned) return { status: "BANNED" };
  const usdAmount = parseFloat(amount_usd);
  const bdtAmount = Math.floor(usdAmount * USD_TO_BDT * (USER_REWARD_PERCENT / 100));
  await User.updateOne({ _id: user._id }, { $inc: { balance: bdtAmount, totalEarned: bdtAmount } });
  await Submission.create({ phone: user.phone, taskTitle: source + " Task", rewardAmt: bdtAmount, status: "APPROVED", siteUsername: source, transactionId: trans_id || "N/A" });
  const today = getDateStr(); const week = getWeekStr();
  const isNewDay = user.lastTaskDate !== today; const isNewWeek = user.lastWeekReset !== week;
  await User.updateOne({ _id: user._id }, { $set: { lastTaskDate: today, lastWeekReset: week, todayTaskCount: isNewDay ? 1 : (user.todayTaskCount || 0) + 1, weekTaskCount: isNewWeek ? 1 : (user.weekTaskCount || 0) + 1, streakBonusPaid: isNewDay ? false : user.streakBonusPaid, weeklyBonusPaid: isNewWeek ? false : user.weeklyBonusPaid } });
  return { status: "OK", amount: bdtAmount };
}

app.get("/api/postback/cpx", async (req, res) => {
  const { user_id, amount_usd, trans_id, status } = req.query;
  if (status !== "1") return res.send("OK");
  const r = await processReward(user_id, amount_usd, trans_id, "CPX");
  if (r.status === "NOT_FOUND") return res.status(404).send("USER_NOT_FOUND");
  if (r.status === "BANNED") return res.status(403).send("USER_BANNED");
  res.send("OK");
});
app.get("/api/postback/adgem", async (req, res) => { const { user_id, amount, trans_id, status } = req.query; if (status !== "1") return res.send("OK"); const r = await processReward(user_id, amount, trans_id, "AdGem"); if (r.status === "NOT_FOUND") return res.status(404).send("USER_NOT_FOUND"); res.send("OK"); });
app.get("/api/postback/timewall", async (req, res) => { const { user_id, amount, trans_id, status } = req.query; if (status !== "1") return res.send("OK"); const r = await processReward(user_id, amount, trans_id, "TimeWall"); if (r.status === "NOT_FOUND") return res.status(404).send("USER_NOT_FOUND"); res.send("OK"); });
app.get("/api/postback/bitcotasks", async (req, res) => {
  const userId = req.query.user_id || req.query.subid;
  const amt = req.query.amount || req.query.payout;
  if (req.query.status && req.query.status !== "1") return res.send("OK");
  if (!userId || !amt) return res.status(400).send("MISSING_PARAMS");
  const r = await processReward(userId, amt, req.query.trans_id, "Bitcotasks");
  if (r.status === "NOT_FOUND") return res.status(404).send("USER_NOT_FOUND");
  res.send("OK");
});

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;
  if (username !== process.env.ADMIN_USER || password !== process.env.ADMIN_PASS) return res.status(401).json({ error: "Wrong" });
  res.json({ token: jwt.sign({ role: "admin" }, process.env.JWT_SECRET, { expiresIn: "7d" }) });
});

app.get("/api/admin/stats", adminAuth, async (req, res) => {
  const [users, subs, ws, pendingSub, pendingW] = await Promise.all([User.countDocuments(), Submission.countDocuments(), Withdrawal.countDocuments(), Submission.countDocuments({ status: "PENDING" }), Withdrawal.countDocuments({ status: "PENDING" })]);
  const totalPaid = await Withdrawal.aggregate([{ $match: { status: "APPROVED" } }, { $group: { _id: null, t: { $sum: "$amount" } } }]);
  res.json({ users, submissions: subs, withdrawals: ws, pendingSub, pendingW, totalPaid: totalPaid[0] ? totalPaid[0].t : 0 });
});

app.get("/api/admin/users", adminAuth, async (req, res) => res.json(await User.find().select("-password").sort({ createdAt: -1 })));
app.post("/api/admin/ban-user", adminAuth, async (req, res) => { const { phone, ban } = req.body; await User.updateOne({ phone }, { isBanned: ban }); res.json({ message: "OK" }); });
app.post("/api/admin/add-balance", adminAuth, async (req, res) => { const { phone, amount } = req.body; await User.updateOne({ phone }, { $inc: { balance: amount, totalEarned: amount } }); res.json({ message: "OK" }); });
app.post("/api/admin/add-task", adminAuth, async (req, res) => res.json(await Task.create(req.body)));
app.get("/api/admin/tasks", adminAuth, async (req, res) => res.json(await Task.find().sort({ createdAt: -1 })));
app.put("/api/admin/task/:id", adminAuth, async (req, res) => res.json(await Task.findByIdAndUpdate(req.params.id, req.body, { new: true })));
app.delete("/api/admin/task/:id", adminAuth, async (req, res) => { await Task.findByIdAndDelete(req.params.id); res.json({ message: "OK" }); });
app.get("/api/admin/submissions", adminAuth, async (req, res) => res.json(await Submission.find().sort({ createdAt: -1 })));
app.post("/api/admin/verify-task", adminAuth, async (req, res) => {
  const { subId, status, rejectReason } = req.body;
  const sub = await Submission.findById(subId);
  if (!sub || sub.status !== "PENDING") return res.status(400).json({ error: "Already" });
  sub.status = status; sub.rejectReason = rejectReason; await sub.save();
  const user = await User.findOne({ phone: sub.phone });
  user.pendingPoints -= sub.rewardAmt;
  if (status === "APPROVED") { user.balance += sub.rewardAmt; user.totalEarned += sub.rewardAmt; }
  await user.save();
  res.json({ message: "OK", sub });
});
app.get("/api/admin/withdrawals", adminAuth, async (req, res) => res.json(await Withdrawal.find().sort({ createdAt: -1 })));
app.post("/api/admin/verify-withdraw", adminAuth, async (req, res) => {
  const { wId, status, rejectReason } = req.body;
  const w = await Withdrawal.findById(wId);
  if (!w || w.status !== "PENDING") return res.status(400).json({ error: "Already" });
  w.status = status; w.rejectReason = rejectReason; await w.save();
  if (status === "REJECTED") await User.updateOne({ phone: w.phone }, { $inc: { balance: w.amount } });
  res.json({ message: "OK", w });
});
app.post("/api/admin/notice", adminAuth, async (req, res) => res.json(await Notice.create(req.body)));
app.get("/api/admin/notices", adminAuth, async (req, res) => res.json(await Notice.find().sort({ createdAt: -1 })));
app.delete("/api/admin/notice/:id", adminAuth, async (req, res) => { await Notice.findByIdAndDelete(req.params.id); res.json({ message: "OK" }); });

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("EARN MONEY Backend on port " + PORT));
'''
open('index.js', 'w').write(code)
print('DONE')
