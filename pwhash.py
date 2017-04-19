#!/usr/bin/env python
# -*- coding: utf-8 -*-

import wx
import hashlib
import string
import random
from passlib.hash import sha512_crypt, sha256_crypt

class PWHashUI(wx.Frame):

    def __init__(self, parent, title):
        super(PWHashUI, self).__init__(parent, title=title)
        self.InitAlgos()
        self.InitUI()
        self.Show()
        self.SetAlgo("MD5")

    def InitAlgos(self):
        self.algos = {}
        self.algos["MD5"] = (lambda p: hashlib.md5(p.encode('utf-8')).hexdigest(), False)
        self.algos["SHA1"] = (lambda p: hashlib.sha1(p.encode('utf-8')).hexdigest(), False)
        self.algos["SHA224"] = (lambda p: hashlib.sha224(p.encode('utf-8')).hexdigest(), False)
        self.algos["SHA256"] = (lambda p: hashlib.sha256(p.encode('utf-8')).hexdigest(), False)
        self.algos["SHA384"] = (lambda p: hashlib.sha384(p.encode('utf-8')).hexdigest(), False)
        self.algos["SHA512"] = (lambda p: hashlib.sha512(p.encode('utf-8')).hexdigest(), False)
        self.algos["Crypt SHA512"] = (lambda p, s: sha512_crypt.encrypt(p, salt=s, rounds=5000), True)
        self.algos["Crypt SHA256"] = (lambda p, s: sha256_crypt.encrypt(p, salt=s, rounds=5000), True)

    def InitUI(self):
        panel = wx.Panel(self)
        sizer = wx.GridBagSizer(5, 5)

        labelAlgo = wx.StaticText(panel, label="Hash Method")
        labelPassword = wx.StaticText(panel, label="Password")
        labelSalt = wx.StaticText(panel, label="Salt")
        labelHash = wx.StaticText(panel, label="Hash")

        self.tcPassword = wx.TextCtrl(panel)
        self.tcPassword.Bind(wx.EVT_TEXT, self.UpdateHash)
        self.tcSalt = wx.TextCtrl(panel)
        self.tcSalt.Bind(wx.EVT_TEXT, self.UpdateHash)
        self.tcHash = wx.TextCtrl(panel, style=wx.TE_READONLY|wx.HSCROLL|wx.TE_DONTWRAP)

        butSalt = wx.Button(panel, label="Generate")
        butSalt.Bind(wx.EVT_BUTTON, self.GenSalt)

        selAlgo = wx.ComboBox(panel, choices=list(self.algos.keys()), style=wx.CB_DROPDOWN|wx.CB_READONLY)
        selAlgo.Bind(wx.EVT_COMBOBOX, self.SelectAlgo)

        sizer.Add(labelAlgo, pos=(0, 0))
        sizer.Add(selAlgo, pos=(0, 1), span=(1, 2))
        sizer.Add(labelPassword, pos=(1, 0))
        sizer.Add(self.tcPassword, pos=(1, 1), span=(1, 2), flag=wx.EXPAND|wx.LEFT|wx.RIGHT)
        sizer.Add(labelSalt, pos=(2, 0))
        sizer.Add(self.tcSalt, pos=(2, 1), flag=wx.EXPAND|wx.LEFT|wx.RIGHT)
        sizer.Add(butSalt, pos=(2, 2))
        sizer.Add(labelHash, pos=(3, 0))
        sizer.Add(self.tcHash, pos=(3, 1), span=(1, 2), flag=wx.EXPAND|wx.LEFT|wx.RIGHT)

        sizer.AddGrowableCol(1)
        panel.SetSizer(sizer)
        sizer.Fit(self)

    def SelectAlgo(self, event):
        self.SetAlgo(event.GetString())

    def SetAlgo(self, name):
        self.algo = self.algos[name]
        if self.algo[1]:
            self.tcSalt.Enable()
        else:
            self.tcSalt.Disable()
        self.UpdateHash()

    def GenSalt(self, _=None):
        # crypt() compatible salt
        charset = string.ascii_letters + string.digits + "./"
        salt = ''.join(random.SystemRandom().choice(charset) for _ in range(16))
        self.tcSalt.SetValue(salt)

    def UpdateHash(self, _=None):
        password = self.tcPassword.GetValue()
        if self.algo[1]:
            salt = self.tcSalt.GetValue()
            if len(salt) == 0:
                self.GenSalt()
                salt = self.tcSalt.GetValue()
            self.tcHash.SetValue(self.algo[0](password, salt))
        else:
            self.tcHash.SetValue(self.algo[0](password))


if __name__ == '__main__':
    app = wx.App()
    PWHashUI(None, title='PWHash')
    app.MainLoop()
