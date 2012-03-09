# -*- coding: utf-8 -*-

import logging
import cStringIO
import traceback

from lastuserapp import app


class LocalVarFormatter(logging.Formatter):
    def formatException(self, ei):
        tb = ei[2]
        while 1:
            if not tb.tb_next:
                break
            tb = tb.tb_next
        stack = []
        f = tb.tb_frame
        while f:
            stack.append(f)
            f = f.f_back
        stack.reverse()

        sio = cStringIO.StringIO()
        traceback.print_exception(ei[0], ei[1], ei[2], None, sio)

        for frame in stack:
            print >> sio
            print >> sio, "Frame %s in %s at line %s" % (frame.f_code.co_name,
                                                         frame.f_code.co_filename,
                                                         frame.f_lineno)
            for key, value in frame.f_locals.items():
                print >> sio, "\t%20s = " % key,
                try:
                    print >> sio, repr(value)
                except:
                    print >> sio, "<ERROR WHILE PRINTING VALUE>"

        s = sio.getvalue()
        sio.close()
        if s[-1:] == "\n":
            s = s[:-1]
        return s

formatter = LocalVarFormatter()

file_handler = logging.FileHandler(app.config['LOGFILE'])
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.WARNING)
app.logger.addHandler(file_handler)
if app.config['ADMINS']:
    mail_handler = logging.handlers.SMTPHandler(app.config['MAIL_SERVER'],
        app.config['DEFAULT_MAIL_SENDER'][1],
        app.config['ADMINS'],
        'lastuser failure',
        credentials=(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD']))
    mail_handler.setFormatter(formatter)
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)
