const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const { body, validationResult, param } = require('express-validator');

const app = express();
app.use(bodyParser.json());

// データベース接続設定
const db = mysql.createConnection({
  host: '127.0.0.1', // データベースホスト
  user: 'root', // MySQLユーザー名
  password: 'g022c1048', // MySQLパスワード
  database: 'absence_requests2', // データベース名
});

db.connect((err) => {
  if (err) {
    console.error('データベース接続エラー:', err);
    return;
  }
  console.log('データベース接続成功');
});

// 共通のSQLエラーハンドリング関数
function handleSqlError(err, res, queryName) {
  console.error(`Error in ${queryName}:`, err);
  return res.status(500).json({
    status: 'error',
    message: 'サーバーエラーが発生しました',
    details: `${queryName} 実行中にエラーが発生しました`,
  });
}

// ログインAPI
app.post(
  '/auth/login',
  [
    // email: 必須、メール形式
    body('email')
      .notEmpty()
      .withMessage('emailは必須です')
      .isEmail()
      .withMessage('有効なメールアドレスを入力してください'),

    // password: 必須、8～16文字、大文字・小文字・数字を含む、特殊記号は不可
    body('password')
      .notEmpty()
      .withMessage('passwordは必須です')
      .isLength({ min: 8, max: 16 })
      .withMessage('パスワードは8～16文字で入力してください')
      .matches(/[a-z]/)
      .withMessage('パスワードには小文字を含めてください')
      .matches(/[A-Z]/)
      .withMessage('パスワードには大文字を含めてください')
      .matches(/\d/)
      .withMessage('パスワードには数字を含めてください')
      .not()
      .matches(/[^a-zA-Z0-9]/)
      .withMessage('パスワードに特殊記号を含めることはできません'),
  ],
  (req, res) => {
    // バリデーション結果の確認
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'error',
        message: '入力データが不正です',
        errors: errors.array(),
      });
    }

    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';

    db.query(sql, [email], async (err, results) => {
      if (err) return handleSqlError(err, res, '/auth/login SELECT query');
      if (err || results.length === 0) {
        return res
          .status(401)
          .send({ message: 'emailかパスワードが間違っています' });
      }

      const user = results[0];

      // パスワード検証
      const isValid = await bcrypt.compare(password, user.password_hash);
      if (!isValid) {
        return res
          .status(401)
          .send({ message: 'emailかパスワードが間違っています' });
      }

      // ログイン成功時
      res.status(200).send({ user });
    });
  }
);

// ユーザー登録API
app.post(
  '/auth/register',
  [
    // email: 必須、メール形式
    body('email')
      .isEmail()
      .withMessage('有効なメールアドレスを入力してください')
      .matches(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)
      .withMessage('メールアドレスの形式が不正です'),

    // password: 必須、8～16文字、大文字・小文字・数字を含む
    body('password')
      .isLength({ min: 8, max: 16 })
      .withMessage('パスワードは8～16文字で入力してください')
      .matches(/[a-z]/)
      .withMessage('パスワードには小文字を含めてください')
      .matches(/[A-Z]/)
      .withMessage('パスワードには大文字を含めてください')
      .matches(/\d/)
      .withMessage('パスワードには数字を含めてください')
      .not()
      .matches(/[^a-zA-Z0-9]/)
      .withMessage('パスワードに特殊記号を含めることはできません'),

    // name: 必須
    body('name').notEmpty().withMessage('名前は必須です'),

    // student_number: role_idが2の場合に必須、9文字固定
    body('student_number')
      .if((value, { req }) => req.body.role_id === 2)
      .notEmpty()
      .withMessage('学籍番号は必須です')
      .isLength({ min: 9, max: 9 })
      .withMessage('学籍番号は9文字固定です')
      .matches(/^[A-Z]\d{3}[A-Z]\d{4}$/)
      .withMessage('学籍番号はA012B3456の形式で入力してください'),

    // department: role_idが2の場合に必須、特定の値のみ許可
    body('department')
      .if((value, { req }) => req.body.role_id === 2)
      .notEmpty()
      .withMessage('学科は必須です')
      .isIn(['IS', 'C2', 'PN', 'AI', 'L2'])
      .withMessage('有効な学科を選択してください'),

    // grade: role_idが2の場合に必須、1～4
    body('grade')
      .if((value, { req }) => req.body.role_id === 2)
      .notEmpty()
      .withMessage('学年は必須です')
      .isInt({ min: 1, max: 4 })
      .withMessage('学年は1～4の値で指定してください'),

    // class: role_idが2の場合に必須、1～5
    body('class')
      .if((value, { req }) => req.body.role_id === 2)
      .notEmpty()
      .withMessage('クラスは必須です')
      .isInt({ min: 1, max: 5 })
      .withMessage('クラスは1～5の値で指定してください'),

    // role_id: 必須、1または2
    body('role_id')
      .notEmpty()
      .withMessage('role_idは必須です')
      .isIn([1, 2])
      .withMessage('role_idは1または2で指定してください'),
  ],
  async (req, res) => {
    // バリデーション結果のチェック
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'error',
        message: '入力データが不正です',
        errors: errors.array(),
      });
    }

    // バリデーションを通過したデータ
    const {
      email,
      password,
      name,
      student_number,
      department,
      grade,
      class: userClass,
      role_id,
    } = req.body;

    // パスワードのハッシュ化
    const hashedPassword = await bcrypt.hash(password, 10);

    // SQLクエリ
    const sql = `
          INSERT INTO users (email, password_hash, name, student_number, department, grade, class, role_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;

    db.query(
      sql,
      [
        email,
        hashedPassword,
        name,
        student_number || null, // role_idが2以外の場合はNULL
        department || null,
        grade || null,
        userClass || null,
        role_id,
      ],
      (err, result) => {
        if (err) return handleSqlError(err, res, '/auth/register INSERT query');
        res.status(201).send({ message: '登録成功' });
      }
    );
  }
);

//申請新規作成

app.post(
  '/requests',
  [
    // student_id: 必須
    body('student_id').notEmpty().withMessage('student_idは必須です'),

    // absence_date: 申請日から3カ月先までの範囲、必須
    body('absence_date')
      .notEmpty()
      .withMessage('公欠日付は必須です')
      .custom((value) => {
        const now = new Date();
        const threeMonthsLater = new Date();
        threeMonthsLater.setMonth(threeMonthsLater.getMonth() + 3);
        const absenceDate = new Date(value);
        if (absenceDate < now || absenceDate > threeMonthsLater) {
          throw new Error(
            '公欠日は現在日付から3カ月先までの範囲で指定してください'
          );
        }
        return true;
      }),

    // activity: 必須
    body('activity').notEmpty().withMessage('activityは必須です'),

    // company_name: 必須
    body('company_name').notEmpty().withMessage('会社名は必須です'),

    // 少なくとも1つの授業情報セットが必須
    body().custom((body) => {
      const fields = [
        body.time_class_information_subject_name &&
          body.time_class_information_instructor,
        body.two_time_class_information_subject_name &&
          body.two_time_class_information_instructor,
        body.three_time_class_information_subject_name &&
          body.three_time_class_information_instructor,
        body.four_time_class_information_subject_name &&
          body.four_time_class_information_instructor,
      ];
      if (!fields.some((field) => field)) {
        throw new Error('少なくとも1つの授業情報セットが必要です');
      }
      return true;
    }),

    // comment: activityが"その他"の場合に必須、100文字以内
    body('comment')
      .if((value, { req }) => req.body.activity === 'その他')
      .notEmpty()
      .withMessage('activityが"その他"の場合、コメントは必須です')
      .isLength({ max: 100 })
      .withMessage('コメントは100文字以内で入力してください'),
  ],
  (req, res) => {
    // バリデーション結果の確認
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'error',
        message: '入力データが不正です',
        errors: errors.array(),
      });
    }

    // データの挿入
    const {
      student_id,
      absence_date,
      activity,
      company_name,
      time_class_information_subject_name,
      time_class_information_instructor,
      two_time_class_information_subject_name,
      two_time_class_information_instructor,
      three_time_class_information_subject_name,
      three_time_class_information_instructor,
      four_time_class_information_subject_name,
      four_time_class_information_instructor,
      comment,
    } = req.body;

    const sql = `
      INSERT INTO registration_details
      (student_id, absence_date, activity, company_name, time_class_information_subject_name,
       time_class_information_instructor, two_time_class_information_subject_name,
       two_time_class_information_instructor, three_time_class_information_subject_name,
       three_time_class_information_instructor, four_time_class_information_subject_name,
       four_time_class_information_instructor, comment)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [
        student_id,
        absence_date,
        activity,
        company_name,
        time_class_information_subject_name,
        time_class_information_instructor,
        two_time_class_information_subject_name,
        two_time_class_information_instructor,
        three_time_class_information_subject_name,
        three_time_class_information_instructor,
        four_time_class_information_subject_name,
        four_time_class_information_instructor,
        comment,
      ],
      (err, result) => {
        if (err) return handleSqlError(err, res, '/requests INSERT query');
        res.status(201).send({ message: '申請成功' });
      }
    );
  }
);

// 公欠申請詳細取得API
app.get(
  '/requests2/:student_id/:id',
  [
    // student_id: 必須、数値
    param('student_id')
      .notEmpty()
      .withMessage('student_idは必須です')
      .isInt()
      .withMessage('student_idは数値で指定してください'),

    // id: 必須、数値
    param('id')
      .notEmpty()
      .withMessage('idは必須です')
      .isInt()
      .withMessage('idは数値で指定してください'),
  ],
  (req, res) => {
    // バリデーション結果の確認
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'error',
        message: '入力データが不正です',
        errors: errors.array(),
      });
    }

    const { student_id, id } = req.params; // パスパラメータから生徒IDと申請IDを取得

    // SQLクエリ
    const sql = `
        SELECT
            absence_date,
            activity,
            company_name,
            status,
            time_class_information_subject_name AS period1_subject,
            time_class_information_instructor AS period1_instructor,
            two_time_class_information_subject_name AS period2_subject,
            two_time_class_information_instructor AS period2_instructor,
            three_time_class_information_subject_name AS period3_subject,
            three_time_class_information_instructor AS period3_instructor,
            four_time_class_information_subject_name AS period4_subject,
            four_time_class_information_instructor AS period4_instructor
        FROM registration_details
        WHERE
            id = ? AND student_id = ?
    `;

    db.query(sql, [id, student_id], (err, results) => {
      if (err) return handleSqlError(err, res, 'request2 SELECT query');

      if (results.length === 0) {
        return res.status(404).send({ message: '申請が見つかりません' });
      }

      res.status(200).send(results[0]);
    });
  }
);

// 公欠申請ID取得 (教員用)
app.get('/requests', (req, res) => {
  const sql = `
      SELECT r.student_id,r.id, r.status, r.created_at, u.student_number, u.department, u.grade, u.class, u.name AS student_name
      FROM registration_details r
      JOIN users u ON r.student_id = u.id
  `;

  db.query(sql, (err, results) => {
    if (err) return handleSqlError(err, res, '/requests(教員) SELECT query');

    if (results.length === 0) {
      return res.status(404).send({ message: '申請が見つかりません' });
    }
    res.status(200).send(results);
  });
});

// 公欠申請ID取得API (生徒用)
app.get(
  '/requests/:student_id',
  [
    // student_id: 必須、数値であること
    param('student_id')
      .notEmpty()
      .withMessage('student_idは必須です')
      .isInt()
      .withMessage('student_idは数値で指定してください'),
  ],
  (req, res) => {
    // バリデーション結果の確認
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'error',
        message: '入力データが不正です',
        errors: errors.array(),
      });
    }

    const { student_id } = req.params;

    const sql = `
        SELECT r.id, r.status, u.student_number, u.department, u.grade, u.class, u.name AS student_name
        FROM registration_details r
        JOIN users u ON r.student_id = u.id
        WHERE r.student_id = ?
    `;

    db.query(sql, [student_id], (err, results) => {
      if (err) return handleSqlError(err, res, '/requests(教師) SELECT query');
      if (results.length === 0) {
        return res.status(404).send({ message: '申請が見つかりません' });
      }
      res.status(200).send(results);
    });
  }
);

// 公欠申請ステータス更新API
app.patch(
  '/requests/:student_id/:id',
  [
    // student_id: 必須、数値
    param('student_id')
      .notEmpty()
      .withMessage('student_idは必須です')
      .isInt()
      .withMessage('student_idは数値で指定してください'),

    // id: 必須、数値
    param('id')
      .notEmpty()
      .withMessage('idは必須です')
      .isInt()
      .withMessage('idは数値で指定してください'),

    // status: 必須、有効な値であること
    body('status')
      .notEmpty()
      .withMessage('statusは必須です')
      .isIn(['承認', '非承認'])
      .withMessage('statusは承認または非承認で指定してください'),
  ],
  (req, res) => {
    // バリデーション結果の確認
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'error',
        message: '入力データが不正です',
        errors: errors.array(),
      });
    }

    const { student_id, id } = req.params; // パスパラメータから生徒IDと申請IDを取得
    const { status } = req.body; // リクエストボディからステータスを取得

    // SQLクエリ
    const sql = `
        UPDATE registration_details
        SET status = ?
        WHERE id = ? AND student_id = ?
    `;

    db.query(sql, [status, id, student_id], (err, result) => {
      if (err) return handleSqlError(err, res, '/requests UPDATE query');

      if (result.affectedRows === 0) {
        return res.status(404).send({
          status: 'error',
          message: '申請が見つかりません',
        });
      }

      res.status(200).send({
        status: 'success',
        message: '申請ステータスが更新されました',
      });
    });
  }
);

// サーバー起動
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`サーバー起動: http://localhost:${PORT}`);
});
