#! /usr/bin/python
# -*- coding: utf-8 -*-

import ldap
import MySQLdb
import re, os
from configread import ConfigSectionMap
from passgen import gen_newpass

# Считываем конфигурацию
try:
    # LDAP section
    AD_URL = ConfigSectionMap('ldap')['adurl']
    AD_USER = ConfigSectionMap('ldap')['aduser']
    AD_PASSWORD = ConfigSectionMap('ldap')['adpassword']
    BASE_DN = ConfigSectionMap('ldap')['basedn']
    filterexp = ConfigSectionMap('misc')['extfilt']
    adattr = ConfigSectionMap('misc')['adattr']
    
    # MySQL section
    DB_HOST = ConfigSectionMap('mysql')['dbhost']
    ASTERISK_HOST = ConfigSectionMap('mysql')['dbhost']
    DB_USER = ConfigSectionMap('mysql')['dbuser']
    DB_PASS = ConfigSectionMap('mysql')['dbpass']
    DB_NAME = ConfigSectionMap('mysql')['dbname']
except Exception as err:
    print("Ошибка конфигурации: %s." % err)

scope = ldap.SCOPE_SUBTREE
attrlist = ["displayName","sAMAccountName", "mail", "pager", adattr, "userAccountControl"]

# Проверка экстеншена на наличие
def check_ext(extnum, extname='', flag=1):
    try:
        DB = MySQLdb.connect(DB_HOST, DB_USER, DB_PASS, DB_NAME, charset='utf8')
    except Exception as e:
        print("Ошибка подключения к БД: %s" % e)
    ch_cursor = DB.cursor()
    if flag == 1:
        sql_ch = "select extension, name from users where extension='%s';" % extnum
    elif flag == 2:
        sql_ch = "select extension, name from users where name='%s';" % extname
    ch_cursor.execute(sql_ch)
    ch_data = ch_cursor.fetchall()
    for ch_rec in ch_data:
        if not ch_rec:
            return False
        elif flag == 2 and ch_rec[0] != extnum:
            return ch_rec[0]
        else:
            return True
    ch_cursor.close()
    DB.close()

# Удаление экстеншена
def del_ext(extnum):
    del_sql = list()
    try:
        DB = MySQLdb.connect(DB_HOST, DB_USER, DB_PASS, DB_NAME, charset='utf8')
    except Exception as e:
        print("Ошибка подключения к БД: %s" % e)
    del_sql.append("delete from users where extension='%s';" % extnum)
    del_sql.append("delete from sip where id='%s';" % extnum)
    del_sql.append("delete from devices where id='%s';" % extnum)
    for sql in del_sql:
        try:
            del_cursor = DB.cursor()
            del_cursor.execute(sql)
            del_cursor.close()
        except Exception as e:
            print("Ошибка удаления: %s" % e)
    DB.commit()
    DB.close()
    os.system('/usr/sbin/rasterisk -x "database del CW %s"' % extnum) # удаляем запись из БД астериска
    
# Создание нового экстеншена
def add_ext(cextnum, cextname, flag, upass=''):
    sql_sip_add = ""
    try:
        DB = MySQLdb.connect(DB_HOST, DB_USER, DB_PASS, DB_NAME, charset='utf8')
    except Exception as e:
        print("Ошибочка: %s" % e)
    add_cursor = DB.cursor()
    if flag == 3:
        sql_sip_add += """insert into sip(id, keyword, data, flags) values ('%(cextnum)s', 'secret', '%(upass)s', 2),"""%{"cextnum":cextnum, "upass":upass}
        sql_sip_add += """('%(cextnum)s', 'dtmfmode', 'rfc2833', 3),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'canreinvite', 'no', 4),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'context', 'from-internal', 5),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'host', 'dynamic', 6),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'defaultuser', '', 7),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'trustrpid', 'yes', 8),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'sendrpid', 'pai', 9),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'type', 'friend', 10),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'sessiontimers', 'accept', 11),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'nat', 'no', 12),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'port', '5060', 13),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'qualify', 'yes', 14),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'qualifyfreq', '60', 15),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'transport', 'udp', 16),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'avpf', 'no', 17),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'force_avp', 'no', 18),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'icesupport', 'no', 19),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'encryption', 'no', 20),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'videosupport', 'inherit', 21),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'namedcallgroup', '', 22),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'namedpickupgroup', '', 23),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'disallow', 'all', 24),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'allow', 'ulaw&alaw', 25),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'dial', 'SIP/%(cextnum)s', 26),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'accountcode', '', 27),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'deny', '0.0.0.0/0.0.0.0', 28),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'permit', '0.0.0.0/0.0.0.0', 29),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'secret_origional', '', 30),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'sipdriver', 'chan_sip', 31),"""%{"cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'account', '%(cextnum)s', 32),"""%{"cextnum":cextnum, "cextnum":cextnum}
        sql_sip_add += """('%(cextnum)s', 'callerid', 'device <%(cextnum)s>', 33);\n"""%{"cextnum":cextnum, "cextnum":cextnum}
    elif flag == 1:    
        sql_sip_add += """insert into users(extension, name, voicemail, ringtimer, password, noanswer, recording, outboundcid, sipname) values ('%(cextnum)s', '%(cextname)s', 'novm', 0, '', '', '', '', '');"""%{"cextnum":cextnum, "cextname":cextname}
    elif flag == 2:
        sql_sip_add += """insert into devices(id, tech, dial, devicetype, user, description, emergency_cid) values ('%(cextnum)s', 'sip', 'SIP/%(cextnum)s', 'fixed', '%(cextnum)s', '%(cextname)s', '');"""%{"cextnum":cextnum, "cextnum":cextnum, "cextnum":cextnum, "cextname":cextname}
    try:
        add_cursor.execute(sql_sip_add)
        DB.commit()
        add_cursor.close()
    except Exception as e:
        print("Шаг: %s.\nОшибка добавления в базу: %s" % (flag, e))
    DB.close()

# Поиск конфига телефона
def find_cfg(ttel):
    out = os.popen('grep -R %s /var/lib/tftpboot/' % ttel)
    st = out.readline()
    out.close()
    if st:
        spatt = '([0-9a-z]+\.cfg)'
        b = re.search(spatt, st)
        return b.group(0).replace('.cfg', '')
    else:
        return False
    
# Запись файла конфига для телефона
def write_cfg(imac, cfgstr):
    path = '/var/lib/tftpboot/'+imac+'.cfg'
    print("Файл конфигурации: %s" % path)
    f = open(path, 'w')
    f.write(cfgstr)
    f.close

try:
    AD = ldap.initialize(AD_URL)
    AD.simple_bind_s(AD_USER, AD_PASSWORD)  
    results = AD.search_s(BASE_DN, scope, filterexp, attrlist)
    for result in results:
        if 'userAccountControl' in result[1].keys():
            UAC = result[1]['userAccountControl'][0]
        tel = result[1]['telephoneNumber'][0]
        disname = result[1]['displayName'][0]
        if UAC == '66050':
            continue
        modext = check_ext(tel, disname, flag=2)
        modmac = find_cfg(tel)
        if 'pager' in result[1].keys():
            newmac = result[1]['pager'][0].lower()
        else:
            newmac = ''
        if len(newmac) == 12 and modmac != newmac and modmac != False:
            print("Изменился мак-адрес у %s... %s->%s" % (disname, modmac, newmac))
            cmdstr = "mv -f /var/lib/tftpboot/%s.cfg /var/lib/tftpboot/%s.cfg" % (modmac, newmac)
            out = os.popen(cmdstr)
            lnout = out.readline()
            out.close()
            print(cmdstr)
            print(lnout)
        elif check_ext(tel):
            continue
        elif not 'pager' in result[1].keys():
            mac_addr = ''
            print("МАС-адрес не задан")
            continue
        elif len(result[1]['pager'][0]) != 12:
            print("Ошибка в MAC-адресе.")
            continue
        elif modext > 0:
            newpass = gen_newpass(11)
            del_ext(modext)
            mac_addr = result[1]['pager'][0].lower()
            add_ext(tel, disname, 1)
            add_ext(tel, disname, 2)
            add_ext(tel, disname, 3, newpass)
            PRE_CFG = """#!version:1.0.0.1\naccount.1.enable = 1\naccount.1.auth_name = %s\naccount.1.display_name = %s\naccount.1.label = %s\naccount.1.password = %s\naccount.1.user_name = %s\naccount.1.outbound_proxy_enable = 0\naccount.1.shared_line = 0\naccount.1.sip_server.1.address = %s\naccount.1.sip_server.1.port = 5060\nsecurity.user_password = admin:Nz$gMgeGWHn"""%(tel, disname, tel, newpass, tel, ASTERISK_HOST)
            write_cfg(mac_addr, PRE_CFG)
            os.system('/usr/sbin/rasterisk -x "database put CW %s ENABLED"' % tel) # добавляем запись CallWaiting в БД астериска
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s answermode disabled"' % tel)
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s cfringtimer 0"' % tel)
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s cidname %s"' % (tel, disname))
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s cidnum %s"' % (tel, tel))
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s concurrency_limit 0"' % tel)
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s device %s"' % (tel, tel))
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s hint SIP/%s,CustomPresence:%s"' % (tel, tel, tel))
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s intercom enabled"' % tel)
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s ringtimer 0"' % tel)
			os.system('/usr/sbin/rasterisk -x "database put AMPUSER/%s voicemail novm"' % tel)
			os.system('/usr/sbin/rasterisk -x "database put DEVICE/%s default_user %s"' % (tel, tel))
			os.system('/usr/sbin/rasterisk -x "database put DEVICE/%s dial SIP/%s"' % (tel, tel))
			os.system('/usr/sbin/rasterisk -x "database put DEVICE/%s type fixed"' % tel)
			os.system('/usr/sbin/rasterisk -x "database put DEVICE/%s user %s"' % (tel, tel))
			
        else:
            mac_addr = result[1]['pager'][0].lower()
            print("Нет экстеншена: %s -> %s. Добавляем..." % (disname, tel))
            userpass = gen_newpass(11)  # Генерируем новый 11-символьный пароль
            add_ext(tel, disname, 1)
            add_ext(tel, disname, 2)
            add_ext(tel, disname, 3, userpass)
            # Генерируем конфиг для телефона
            PRE_CFG = """#!version:1.0.0.1\naccount.1.enable = 1\naccount.1.auth_name = %s\naccount.1.display_name = %s\naccount.1.label = %s\naccount.1.password = %s\naccount.1.user_name = %s\naccount.1.outbound_proxy_enable = 0\naccount.1.shared_line = 0\naccount.1.sip_server.1.address = %s\naccount.1.sip_server.1.port = 5060\nsecurity.user_password = admin:Nz$gMgeGWHn"""%(tel, disname, tel, userpass, tel, ASTERISK_HOST)
            write_cfg(mac_addr, PRE_CFG)
            os.system('/usr/sbin/rasterisk -x "database put CW %s ENABLED"' % tel) # добавляем запись CallWaiting в БД астериска
    AD.unbind_s()
except Exception as e:
    print("Ошибка глобальная: %s" % e)
