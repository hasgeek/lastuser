Hello {{ user.fullname }},

You or someone claiming to be you asked for your password to be reset.

[Click here to reset your password][reset].

[reset]: {{ url_for('.reset_email', _external=True, userid=user.userid, secret=secret) }}

If you did not ask for your password to be reset, you may safely ignore this
email.
