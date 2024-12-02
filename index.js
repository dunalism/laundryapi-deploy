"use strict";

const express = require("express");
const dotenv = require("dotenv");
const pkg = require("bcryptjs");
const pkg2 = require("jsonwebtoken");
const sqlite3 = require("sqlite3");
const sqlite = require("sqlite");
const logger = require("morgan");
const path = require("path");

let db;

async function initializeDatabase() {
  try {
    db = await sqlite.open({
      filename: "./dlsmlaundry.db", // Nama file database SQLite
      driver: sqlite3.Database,
    });

    // Mengaktifkan foreign-key support
    await db.exec("PRAGMA foreign_keys = ON");
  } catch (error) {
    console.error("Error connecting to the SQLite database:", error.message);
  }
  return db;
}

// Mendapatkan semua users
const getAllUsers = async (callback) => {
  const sql = "SELECT * FROM users";
  try {
    const db = await initializeDatabase(); // Memastikan `db` diinisialisasi
    const results = await db.all(sql);
    callback(null, results);
  } catch (err) {
    callback(err);
  }
};

// Mendapatkan user berdasarkan id
const getUserById = async (id, callback) => {
  const query = "SELECT * FROM users WHERE id = ?";
  try {
    const db = await initializeDatabase();
    const result = await db.get(query, [id]);
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

// REGISTER - Menambahkan user baru
const addUser = async (name, username, email, password, callback) => {
  const sql = `INSERT INTO users (name, username, email, password, role) VALUES (?, ?, ?, ?, ?)`;
  try {
    const db = await initializeDatabase();
    const result = await db.run(sql, [name, username, email, password, "user"]);
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

// Login
const login = async (username, callback) => {
  const sql = "SELECT * FROM users WHERE username = ?";
  try {
    const db = await initializeDatabase();
    const result = await db.get(sql, [username]);
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

// Update user
const putUsers = async (
  name,
  username,
  email,
  password,
  role,
  id,
  callback
) => {
  const sql = `UPDATE users SET name = ?, username = ?, email = ?, password = ?, role = ? WHERE id = ?`;
  try {
    const db = await initializeDatabase();
    const result = await db.run(sql, [
      name,
      username,
      email,
      password,
      role,
      id,
    ]);
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

// Update user oleh owner
const ownerPutUsers = async (
  name,
  username,
  email,
  password,
  role,
  id,
  callback
) => {
  const sql = `UPDATE users SET name = ?, username = ?, email = ?, password = ?, role = ? WHERE id = ?`;
  try {
    const db = await initializeDatabase();
    const result = await db.run(sql, [
      name,
      username,
      email,
      password,
      role,
      id,
    ]);
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

// Delete user
const deleteUsers = async (id, callback) => {
  const sql = "DELETE FROM users WHERE id = ?";
  try {
    const db = await initializeDatabase();
    const result = await db.run(sql, [id]);
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const { hashSync, compare, compareSync, hash } = pkg;
const { sign } = pkg2;

express.Router();

// Mendapatkan semua user
const getUsers = (req, res) => {
  getAllUsers((err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(200).json({ status: "200 OK", data: users.slice(1) });
  });
};

// Mendapatkan profil pengguna berdasarkan userId dari token
const getUserProfile = (req, res) => {
  const userId = req.userId; // userId sudah didekode oleh middleware

  getUserById(userId, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ message: "User not found" });

    res.status(200).json({ status: "200 OK", data: user });
  });
};

const getUser = (req, res) => {
  const { id } = req.params;
  const role = req.userRole;
  if (id == 1 && role != "owner")
    return res
      .status(403)
      .json({ message: "You don't have authority over that resource" });

  getUserById(id, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ message: "User not found" });

    res.status(200).json({ status: "200 OK", data: user });
  });
};

// REGISTER
const createUser = async (req, res) => {
  const { name, username, email, password } = req.body;

  const hashedPassword = password ? await hash(password, 9) : undefined;

  //
  //

  if (!name || !username || !email || !hashedPassword) {
    return res.status(400).json({ error: "Invalid request body" });
  }

  addUser(name, username, email, hashedPassword, (err, result) => {
    const sameUsername = err?.errno == 19 ? true : false;
    if (err && !sameUsername) {
      return res.status(500).json({ error: err.message });
    } //handle error connection to database

    if (sameUsername)
      return res.status(400).json({
        error: `${username} is already registered, please use another username`,
      });

    res.status(201).json({
      message: "User registered successfully",
      result: result,
      data: {
        name: name,
        username: username,
        email: email,
        role: "user",
      },
    });
  });
};

//LOGIN
const loginUser = (req, res) => {
  const { username, password } = req.body;
  login(username, (err, result) => {
    if (err) {
      console.log("err", err);
      return res.status(500).json({ error: err.message });
    } //handle error connecting to database

    if (!username || !password)
      return res.status(400).json({ error: "Invalid request body" });

    const user = result;
    if (user) {
      const passwordIsValid = compareSync(password, user.password);

      if (passwordIsValid) {
        const secret = process.env.JWT_SECRET || "secret";
        const token = sign({ id: user.id, role: user.role }, secret, {
          expiresIn: 86400,
        });
        res.status(200).json({
          auth: true,
          token: token,
          data: {
            name: user.name,
            username: user.username,
            email: user.email,
            role: user.role,
            createdAt: user.createdAt,
          },
        });
      } else {
        res
          .status(401)
          .json({ auth: false, token: null, error: "Invalid password" });
      }
    } else {
      res.status(401).json({
        auth: false,
        token: null,
        error: "Invalid username or password",
      });
    }
  });
};

const updateUser = (req, res) => {
  const { name, username, email, password } = req.body;
  const role = req.userRole;
  const userId = req.userId;
  const hashedPassword = hashSync(password, 7);
  if (!name || !username || !email || !hashedPassword) {
    return res.status(400).json({ error: "Invalid request body" });
  }

  putUsers(
    name,
    username,
    email,
    hashedPassword,
    role,
    userId,
    (err, result) => {
      const sameUsername = err?.errno == 19 ? true : false;

      if (err && !sameUsername)
        return res.status(500).json({ error: err.message });

      if (sameUsername)
        return res.status(400).json({
          error: `${username} is already registered, please use another username`,
        });

      if (result?.warningStatus > 0)
        return res
          .status(400)
          .json({ error: "invalid role, role must admin or user" });

      if (result.changes === 0) {
        return res
          .status(400)
          .json({ error: "No rows updated. User ID not found" });
      }

      getUserById(userId, (err, result2) => {
        res.status(201).json({
          message: "User updated successfully",
          result: result,
          data: {
            id: userId,
            name: name,
            username: username,
            email: email,
            role: role,
            createdAt: result2.createdAt,
          },
        });
      });
    }
  );
};

const ownerUpdateUser = (req, res) => {
  const { name, username, email, password, role } = req.body;
  const { id } = req.params;
  // const theRole = req.userRole !== "owner" ? undefined : role;
  const hashedPassword = hashSync(password, 7);
  if (!name || !username || !email || !hashedPassword) {
    return res.status(400).json({ error: "Invalid request body" });
  }

  // if (!theRole) return res.status(403).json({ error: "Require owner role" });

  ownerPutUsers(
    name,
    username,
    email,
    hashedPassword,
    role,
    id,
    (err, result) => {
      const sameUsername = err?.errno == 19 ? true : false;

      if (err && !sameUsername)
        return res.status(500).json({ error: err.message });

      if (sameUsername)
        return res.status(400).json({
          error: `${username} is already registered, please use another username`,
        });

      if (result?.warningStatus > 0)
        return res
          .status(400)
          .json({ error: "invalid role, role must admin or user" });

      if (result.changes === 0) {
        return res
          .status(400)
          .json({ error: "No rows updated. User ID not found" });
      }

      getUserById(id, (err, result2) => {
        res.status(201).json({
          message: "User updated successfully",
          result: result,
          data: {
            id: id,
            name: name,
            username: username,
            email: email,
            role: role,
            createdAt: result2.createdAt,
          },
        });
      });
    }
  );
};

const deleteUser = (req, res) => {
  const { id } = req.params;
  const role = req.userRole;

  if (id == 1 && role != "owner")
    return res
      .status(400)
      .json({ message: "You don't have authority over that method" });

  if (id == 1 && role == "owner")
    return res.status(400).json({
      message:
        "You are the owner, if you delete your own account who becomes the owner?",
    });

  deleteUsers(id, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.changes === 0) {
      return res
        .status(400)
        .json({ error: "No rows deleted. User ID not found" });
    }

    res
      .status(200)
      .json({ message: "User deleted successfullly", result: result });
  });
};

// Middleware untuk memverifikasi token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]; // Ambil token dari header Authorization
  if (!authHeader) {
    return res.status(403).json({ auth: false, message: "No token provided" });
  }

  // Token format: 'Bearer [token]'
  const token = authHeader.split(" ")[1]; // Pisahkan "Bearer" dan token

  // Verifikasi token
  pkg2.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(401).json({ auth: false, message: "Invalid token" });

    // Simpan userId ke request untuk digunakan nanti
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

const verifyRole = (requiredRole) => {
  return (req, res, next) => {
    const userRole = req.userRole;

    if (userRole !== requiredRole) {
      return res.status(403).json({ message: `Require ${requiredRole} role` });
    }

    next();
  };
};

const verifyRoles = (req, res, next) => {
  const userRole = req.userRole;

  if (userRole === "admin" || userRole === "owner") {
    next();
  } else {
    res.status(403).json({ message: `Require owner or admin role` });
  }
};

const router$3 = express.Router();

//authentication
router$3.post("/auth/register", createUser);
router$3.post("/auth/login", loginUser);

//owner
router$3.put(
  "/owner/users/:id",
  verifyToken,
  verifyRole("owner"),
  ownerUpdateUser
);

//owner and admin
router$3.get("/admin/users", verifyToken, verifyRoles, getUsers);
router$3.delete("/admin/users/:id", verifyToken, verifyRoles, deleteUser);

//all
router$3.get("/users/:id", verifyToken, getUser);
router$3.get("/profile", verifyToken, getUserProfile);
router$3.put("/profile", verifyToken, updateUser);

const getAllProducts = async (callback) => {
  const sql = "SELECT * FROM products";
  try {
    const db = await initializeDatabase();
    const results = await db.all(sql); // Menggunakan .all() untuk mendapatkan semua data
    callback(null, results);
  } catch (err) {
    callback(err);
  }
};

const getProductById = async (id, callback) => {
  const query = "SELECT * FROM products WHERE id = ?";
  try {
    const db = await initializeDatabase();
    const result = await db.get(query, [id]); // Menggunakan .get() untuk satu data
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const addProductq = async (name, price, type, callback) => {
  const sql = `INSERT INTO products (name, price, type) VALUES (?, ?, ?)`;
  try {
    const db = await initializeDatabase();
    const result = await db.run(sql, [name, price, type]); // Menggunakan .run() untuk operasi INSERT
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const putProduct = async (name, price, type, id, callback) => {
  const sql = `UPDATE products SET name = ?, price = ?, type = ? WHERE id = ?`;
  const values = [name, price, type, id];
  try {
    const db = await initializeDatabase();
    const result = await db.run(sql, values); // Menggunakan .run() untuk operasi UPDATE
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const deleteProductq = async (id, callback) => {
  const sql = "DELETE FROM products WHERE id = ?";
  try {
    const db = await initializeDatabase();
    const result = await db.run(sql, [id]); // Menggunakan .run() untuk operasi DELETE
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const getProducts = (req, res) => {
  getAllProducts((err, products) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(200).json({ status: "200 OK", data: products });
  });
};

const getProduct = (req, res) => {
  const { id } = req.params;

  getProductById(id, (err, product) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!product) return res.status(404).json({ message: "Product not found" });

    res.status(200).json({ status: "200 OK", data: product });
  });
};

const createProduct = (req, res) => {
  const { name, price, type } = req.body;

  if (!name || !price || !type)
    return res.status(400).json({ error: "invalid request body" });

  addProductq(name, price, type, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    getProductById(result.lastID, (err, result2) => {
      res.status(201).json({
        message: "Product added successfully",
        result: result,
        data: {
          id: result.lastID,
          name,
          price,
          type,
          createdAt: result2.createdAt,
        },
      });
    });
  });
};

const editProduct = (req, res) => {
  const { name, price, type } = req.body;
  const { id } = req.params;

  if (!name || !price || !type) {
    return res.status(400).json({ error: "Invalid request body" });
  }

  putProduct(name, price, type, id, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    if (result.changes === 0) {
      return res
        .status(400)
        .json({ error: "No rows updated. Product ID not found" });
    }
    getProductById(id, (err, result2) => {
      res.status(201).json({
        message: "Product updated successfully",
        result: result,
        data: {
          id: id,
          name,
          price,
          type,
          createdAt: result2.createdAt,
        },
      });
    });
  });
};

const deleteProduct = (req, res) => {
  const { id } = req.params;

  deleteProductq(id, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    if (result.changes === 0) {
      return res
        .status(400)
        .json({ error: "No rows deleted. Product ID not found" });
    }

    res
      .status(200)
      .json({ message: "Product deleted successfullly", result: result });
  });
};

const router$2 = express.Router();

router$2.get("/products", verifyToken, getProducts);
router$2.get("/products/:id", verifyToken, getProduct);

//owner
router$2.post("/products", verifyToken, verifyRole("owner"), createProduct);
router$2.put("/products/:id", verifyToken, verifyRole("owner"), editProduct);
router$2.delete(
  "/products/:id",
  verifyToken,
  verifyRole("owner"),
  deleteProduct
);

const getCustomersq = async (callback) => {
  const db = await initializeDatabase();
  const sql = "SELECT * FROM customers";
  try {
    const results = await db.all(sql); // Mengambil semua data customers
    callback(null, results);
  } catch (err) {
    callback(err);
  }
};

const getCustomersById = async (id, callback) => {
  const db = await initializeDatabase();
  const query = "SELECT * FROM customers WHERE id = ?";
  try {
    const result = await db.get(query, [id]); // Mengambil satu data customer berdasarkan id
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const addCustomer = async (name, phoneNumber, address, callback) => {
  const db = await initializeDatabase();
  const sql = `INSERT INTO customers (name, phoneNumber, address) VALUES (?, ?, ?)`;
  try {
    const result = await db.run(sql, [name, phoneNumber, address]); // Menambahkan data customer baru
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const putCustomer = async (name, phoneNumber, address, id, callback) => {
  const db = await initializeDatabase();
  const sql = `UPDATE customers SET name = ?, phoneNumber = ?, address = ? WHERE id = ?`;
  const values = [name, phoneNumber, address, id];
  try {
    const result = await db.run(sql, values); // Memperbarui data customer
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const deleteCustomerq = async (id, callback) => {
  const db = await initializeDatabase();
  const sql = "DELETE FROM customers WHERE id = ?";
  try {
    const result = await db.run(sql, [id]); // Menghapus data customer berdasarkan id
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const getCustomers = (req, res) => {
  getCustomersq((err, customers) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(200).json({ status: "200 OK", data: customers });
  });
};

const getCustomer = (req, res) => {
  const { id } = req.params;

  getCustomersById(id, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ message: "Customer not found" });

    res.status(200).json({ status: "200 OK", data: user });
  });
};

const createCustomer = (req, res) => {
  const { name, phoneNumber, address } = req.body;

  if (!name || !phoneNumber || !address)
    return res.status(400).json({ error: "invalid request body" });

  addCustomer(name, phoneNumber, address, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    getCustomersById(result.lastID, (err, result2) => {
      res.status(201).json({
        message: "Customer added successfully",
        result: result,
        data: {
          id: result.lastID,
          name,
          phoneNumber,
          address,
          createdAt: result2.createdAt,
        },
      });
    });
  });
};

const editCustomer = (req, res) => {
  const { name, phoneNumber, address } = req.body;
  const { id } = req.params;

  if (!name || !phoneNumber || !address) {
    return res.status(400).json({ error: "Invalid request body" });
  }

  putCustomer(name, phoneNumber, address, id, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    if (result.changes === 0) {
      return res
        .status(400)
        .json({ error: "No rows updated. Customer ID not found" });
    }
    getCustomersById(id, (err, result2) => {
      res.status(201).json({
        message: "Customer updated successfully",
        result: result,
        data: {
          id: id,
          name,
          phoneNumber,
          address,
          createdAt: result2.createdAt,
        },
      });
    });
  });
};

const deleteCustomer = (req, res) => {
  const { id } = req.params;

  deleteCustomerq(id, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    if (result.changes === 0) {
      return res
        .status(400)
        .json({ error: "No rows deleted. Customer ID not found" });
    }

    res
      .status(200)
      .json({ message: "Customer deleted successfullly", result: result });
  });
};

const router$1 = express.Router();

//owner and admin
router$1.get("/customers", verifyToken, verifyRoles, getCustomers);
router$1.get("/customers/:id", verifyToken, verifyRoles, getCustomer);
router$1.post("/customers", verifyToken, verifyRoles, createCustomer);
router$1.put("/customers/:id", verifyToken, verifyRoles, editCustomer);
router$1.delete("/customers/:id", verifyToken, verifyRoles, deleteCustomer);

const getAllTransactions = async (callback) => {
  const db = await initializeDatabase();
  const sql = `SELECT 
    users.id AS user_id,
    users.name AS user_name,
    users.email AS user_email,
    users.role AS user_role,
    customers.id AS customers_id,
    customers.name AS customers_name,
    customers.phoneNumber AS customers_phone,
    customers.address AS customers_address,
    transaksi.id AS transaksi_id,
    transaksi.quantity AS transaksi_quantity,
    transaksi.total_price AS transaksi_total_price,
    transaksi.transaction_date AS transaksi_date,
    products.id AS product_id,
    products.name AS product_name,
    products.price AS product_price,
    products.type AS product_type
  FROM 
    transaksi
  JOIN 
    customers ON transaksi.customer_id = customers.id
  JOIN 
    products ON transaksi.product_id = products.id
  JOIN 
    users ON transaksi.user_id = users.id`;

  try {
    const results = await db.all(sql);
    callback(null, results);
  } catch (err) {
    callback(err);
  }
};

const getTransactionById = async (id, callback) => {
  const db = await initializeDatabase();
  const query = `SELECT 
    users.id AS user_id,
    users.name AS user_name,
    users.email AS user_email,
    users.role AS user_role,
    customers.id AS customers_id,
    customers.name AS customers_name,
    customers.phoneNumber AS customers_phone,
    customers.address AS customers_address,
    transaksi.id AS transaksi_id,
    transaksi.quantity AS transaksi_quantity,
    transaksi.total_price AS transaksi_total_price,
    transaksi.transaction_date AS transaksi_date,
    products.id AS product_id,
    products.name AS product_name,
    products.price AS product_price,
    products.type AS product_type
  FROM 
    transaksi
  JOIN 
    customers ON transaksi.customer_id = customers.id
  JOIN 
    products ON transaksi.product_id = products.id
  JOIN 
    users ON transaksi.user_id = users.id
  WHERE 
    transaksi.id = ?`;

  try {
    const results = await db.get(query, [id]);
    callback(null, results);
  } catch (err) {
    callback(err);
  }
};

const getProductPrice = async (id, callback) => {
  const db = await initializeDatabase();
  const query = "SELECT price FROM products WHERE id = ?";

  try {
    const result = await db.get(query, [id]);
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const addTransaction = async (
  user_id,
  customer_id,
  product_id,
  quantity,
  total_price,
  callback
) => {
  const db = await initializeDatabase();
  const sql = `INSERT INTO transaksi (user_id, customer_id, product_id, quantity, total_price) VALUES (?, ?, ?, ?, ?)`;

  try {
    const result = await db.run(sql, [
      user_id,
      customer_id,
      product_id,
      quantity,
      total_price,
    ]);
    callback(null, result);
  } catch (err) {
    callback(err);
  }
};

const getTransactions = (req, res) => {
  getAllTransactions((err, transct) => {
    if (err) return res.status(500).json({ error: err.message });
    const datas = transct.map(
      ({
        transaksi_id,
        transaksi_date,
        customers_id,
        customers_name,
        customers_phone,
        customers_address,
        user_id,
        user_name,
        user_email,
        user_role,
        product_id,
        product_name,
        product_price,
        product_type,
        transaksi_quantity,
        transaksi_total_price,
      }) => ({
        id: transaksi_id,
        transcDate: transaksi_date,
        customer: {
          id: customers_id,
          name: customers_name,
          phoneNumber: customers_phone,
          address: customers_address,
        },
        admin: {
          id: user_id,
          name: user_name,
          email: user_email,
          role: user_role,
        },
        transcDetail: {
          product: {
            id: product_id,
            name: product_name,
            price: product_price,
            type: product_type,
          },
          qty: transaksi_quantity,
          totalPrice: transaksi_total_price,
        },
      })
    );

    res.status(200).json({ status: "200 OK", data: datas });
  });
};

const getTransaction = (req, res) => {
  const { id } = req.params;

  getTransactionById(id, (err, transc) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!transc)
      return res.status(404).json({ message: "Transaction not found" });

    const datas = {
      id: transc.transaksi_id,
      transcDate: transc.transaksi_date,
      customer: {
        id: transc.customers_id,
        name: transc.customers_name,
        phoneNumber: transc.customers_phone,
        address: transc.customers_address,
      },
      admin: {
        id: transc.user_id,
        name: transc.user_name,
        email: transc.user_email,
        role: transc.user_role,
      },
      transcDetail: {
        product: {
          id: transc.product_id,
          name: transc.product_name,
          price: transc.product_price,
          type: transc.product_type,
        },
        qty: transc.transaksi_quantity,
        totalPrice: transc.transaksi_total_price,
      },
    };

    res.status(200).json({ status: "200 OK", data: datas });
  });
};

const createTransaction = (req, res) => {
  const { customerId, productId, qty } = req.body;
  const userId = req.userId;

  if (!customerId || !productId || !qty)
    return res.status(400).json({ error: "invalid request body" });

  getProductPrice(productId, (err, result) => {
    if (!result) return res.status(404).json({ error: "Product ID not found" });

    const totalPrice = result.price * qty;

    addTransaction(
      userId,
      customerId,
      productId,
      qty,
      totalPrice,
      (err, result) => {
        const custIdNotFound = err?.code === "SQLITE_CONSTRAINT";
        if (custIdNotFound)
          return res.status(404).json({ error: "Customer ID not found" });

        if (err) return res.status(500).json({ error: err });

        getTransactionById(result.lastID, (err, transc) => {
          const datas = {
            id: transc.transaksi_id,
            transcDate: transc.transaksi_date,
            customer: {
              id: transc.customers_id,
              name: transc.customers_name,
              phoneNumber: transc.customers_phone,
              address: transc.customers_address,
            },
            admin: {
              id: transc.user_id,
              name: transc.user_name,
              email: transc.user_email,
              role: transc.user_role,
            },
            transcDetail: {
              product: {
                id: transc.product_id,
                name: transc.product_name,
                price: transc.product_price,
                type: transc.product_type,
              },
              qty: transc.transaksi_quantity,
              totalPrice: transc.transaksi_total_price,
            },
          };

          res.status(201).json({
            message: "Transaction added successfully",
            data: datas,
          });
        });
      }
    );
  });
};

const router = express.Router();

//
router.get("/transactions", verifyToken, verifyRoles, getTransactions);
router.get("/transactions/:id", verifyToken, verifyRoles, getTransaction);
router.post("/transactions", verifyToken, verifyRoles, createTransaction);

// Load environment variables
dotenv.config();

const app = express();
const HOST = process.env.DB_HOST || "127.0.0.1";
const PORT = process.env.PORT || 5000;

const cors = require("cors");

const corsOrigin = process.env.ORIGIN || "*";

app.use(cors({ origin: process.env.ORIGIN }));

// Middleware untuk parsing JSON
app.use(express.json());
// Middleware untuk logging
app.use(logger("dev"));

// Routing
app.use("/api/v1", router$3, router$2, router$1, router);

app.use((req, res, next) => {
  res.status(404).json({ error: "The resource not found" });
  console.error(
    "The resource not found. Please check documentation https://github.com/dunalism/laundryapi"
  );
});

// Jalankan server
app.listen(PORT, () => {
  console.log(`Server running on http://${HOST}:${PORT}/api/v1`);
});
