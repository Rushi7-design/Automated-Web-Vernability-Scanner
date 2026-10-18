"""routes/auth.py — Authentication routes: register, login, logout, profile."""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from bson.objectid import ObjectId
from database import db, User

auth_bp = Blueprint("auth", __name__)


# ── LANDING PAGE ──────────────────────────────────────────────────────────────
@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("scan.dashboard"))
    return render_template("index.html")


# ── LOGIN ─────────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("scan.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user = User.find_by_username(username)
        if user and user.check_password(password):
            if not getattr(user, "is_active", True):
                flash("Your account has been deactivated. Contact an administrator.", "error")
                return render_template("auth/login.html")
            login_user(user, remember=remember)
            
            # Update last login
            db.users.update_one({"_id": ObjectId(user.id)}, {"$set": {"last_login": datetime.utcnow()}}) if 'datetime' in globals() else None
            from datetime import datetime
            db.users.update_one({"_id": ObjectId(user.id)}, {"$set": {"last_login": datetime.utcnow()}})
            
            flash(f"Welcome back, {user.username}! 👋", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("scan.dashboard"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("auth/login.html")


# ── REGISTER ──────────────────────────────────────────────────────────────────
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("scan.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        role     = request.form.get("role", "analyst")

        if not username or len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif User.find_by_username(username):
            flash("Username already taken.", "error")
        else:
            # First user becomes admin automatically
            is_first = db.users.count_documents({}) == 0
            User.create(username, password, role="admin" if is_first else role)
            
            if is_first:
                flash("Admin account created! You have full system access.", "success")
            else:
                flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


# ── LOGOUT ────────────────────────────────────────────────────────────────────
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out securely.", "info")
    return redirect(url_for("auth.index"))


# ── PROFILE ───────────────────────────────────────────────────────────────────
@auth_bp.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


# ── CHANGE PASSWORD ───────────────────────────────────────────────────────────
@auth_bp.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    current_pw = request.form.get("current_password", "")
    new_pw     = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    if not current_user.check_password(current_pw):
        flash("Current password is incorrect.", "error")
    elif len(new_pw) < 6:
        flash("New password must be at least 6 characters.", "error")
    elif new_pw != confirm_pw:
        flash("New passwords do not match.", "error")
    else:
        current_user.set_password(new_pw)
        db.users.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {"password_hash": current_user.password_hash}}
        )
        flash("Password updated successfully! 🔐", "success")

    return redirect(url_for("auth.profile"))
