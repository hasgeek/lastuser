Hello {{ useremail.user.fullname }},

[Click here to confirm your email address][confirm].

[confirm]: {{ url_for('confirm_email', _external=True, md5sum=useremail.md5sum, secret=useremail.verification_code) }}

If you did not sign up, you may safely ignore this email.
