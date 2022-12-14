const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const {check, validationResult} = require("express-validator");
const User = require("../models/User");
const {Router} = require("express");
const router = Router();


// /api/auth/register
router.post(
	"/register",
	[
		check("email", "Некорректный email").isEmail(),
		check("password", "Минимальная длина пароля 6 символов").isLength({
			min: 6,
		}),
	],
	async (req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return res.status(400).json({
					errors: errors.array(),
					message: "Некорректные данные при регистрации",
				});
			}

			const {email, password} = req.body;

			const candidate = await User.findOne({email});
			if (candidate) {
				return res
					.status(400)
					.json({message: "Такой пользователь уже существует"});
			}
			const heshedPassword = await bcrypt.hash(password, 15);
			const user = new User({email, password: heshedPassword});

			await user.save();

			res.status(201).json({message: "Пользователь создан"});
		} catch (e) {
			res.status(500).json({message: "Что-то не так, но вы держитесь"});
		}
	}
);
// /api/auth/login
router.post(
	"/login",
	[
		check("email", "Некорректный email").isEmail(),
		check("password", "Минимальная длина пароля 6 символов").isLength({
			min: 6,
		}),
	],
	async (req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return res.status(400).json({
					errors: errors.array(),
					message: "Некорректные данные при входе",
				});
			}

			const {email, password} = req.body;

			const user = await User.findOne({email}).lean();
			if (!user) {
				return res
					.status(400)
					.json({message: "Неверные данные при авторизации"});
			}

			const isMatch = await bcrypt.compare(password, user.password)

			if (!isMatch) {
				return res
					.status(400)
					.json({message: "Неверные данные при авторизации"});
			}

			const token = jwt.sign(
				{userId: user._id},
				config.get('jwtSecret'),
				{expiresIn: '1h'}
			)

			res.status(200).json({token, userId: user._id, message: "Новый пользователь зашел на сайт"})
		} catch
			(e) {
			res.status(500).json({message: "Что-то не так, но вы держитесь"})
		}
	}
)
;

module.exports = router;
