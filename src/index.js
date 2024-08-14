const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = 8080;
const SECRET_KEY = "mhmh_secret_key"; // 토큰 서명을 위한 비밀키

// request의 body에 들어오는 데이터를 json형식으로 파싱해서 객체로 변환해줌. 변환된 객체는 req.body에 담김.
app.use(express.json());

// 사용자 저장
let users = []; 

// 회원가입 라우트
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    // 비밀번호 해싱
    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({ username, password: hashedPassword });

    res.json({ message: "사용자 저장에 성공했습니다!" });
});

// 로그인 라우트
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    // 사용자명 확인
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ message: "사용자명이 유효하지 않습니다." });
    }
    
    // 비밀번호 확인
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: "비밀번호가 유효하지 않습니다." });
    }

    // jwt 생성
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: "1h" });

    res.json({ token });
});

// 보호된 라우트 예시
app.get("/protected", (req, res) => {
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(401).json({ message: "Token is missing" });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        res.json({ message: "This is protected data", user: decoded });
    } catch (error) {
        res.status(401).json({ message: "Invalid or expire token" });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
