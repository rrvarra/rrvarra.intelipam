from flask import render_template, flash
from app import app, ipam, start_ts, autoproxy_instance
from .forms import AutoproxyLookupForm, LookupForm
import re
import logging
import socket

# ----------------------------------------------------------------------------------------------------------------------
def reverse_lookup(ip_to_lookup):
    try:
        ninfos = socket.gethostbyaddr(ip_to_lookup)
        if ninfos:
            return ninfos[0]
    except:
        pass
    return ''

# ----------------------------------------------------------------------------------------------------------------------
def drop_duplicates(l):
    known_set = set()
    def is_known(item):
        if item in known_set:
            return True
        known_set.add(item)
        return False

    return [item for item in l if not is_known(item)]

def get_ipam_file():
    if ipam:
        return ipam.get_ipam_file()
    return "NOT_LOADED"

# ----------------------------------------------------------------------------------------------------------------------
@app.route('/', methods=['GET'])
def index():
    logging.info("View Index")
    lookup_form = LookupForm()
    autoproxy_form = AutoproxyLookupForm()
    return render_template('index.html', lookup_form=lookup_form, autoproxy_form=autoproxy_form, ipam_file=get_ipam_file(), start_ts=start_ts)

@app.route('/ipam_lookup', methods=['POST'])
def ipam_lookup():
    logging.info("View Index")
    lookup_form = LookupForm()
    autoproxy_form = AutoproxyLookupForm()

    do_rl = lookup_form.do_dns_reverse_lookup.data
    ip_infos = []

    if ipam:
        ip_text = lookup_form.ip_address.data or ''
        ip_text = ip_text.strip()
        if ip_text and lookup_form.validate_on_submit():
            logging.info('IP Address : {}'.format(ip_text))
            ip_list = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', ip_text)
            ip_list = drop_duplicates(ip_list)
            for ip_to_lookup in ip_list:
                logging.info("Looking up ip: %s", ip_to_lookup)
                ip_info = ipam.lookup_ip(ip_to_lookup)
                if ip_info:
                    host = reverse_lookup(ip_to_lookup) if do_rl else ''
                    ip_info['Host'] = host
                    ip_info['IP'] = ip_to_lookup
                    ip_infos.append(ip_info.copy())
                    logging.info("Found %s", ip_info)
            if not ip_infos:
                flash(f"Could not find IP: {ip_list}")
    else:
        flash("No IPAM Module loaded: can not do lookups")

    return render_template('index.html', lookup_form=lookup_form, autoproxy_form=autoproxy_form, ip_infos=ip_infos, ipam_file=get_ipam_file(), start_ts=start_ts)

@app.route('/autoproxy_lookup', methods=['POST'])
def autoproxy_lookup():
    logging.info("AutoProxy Index")
    lookup_form = LookupForm()
    autoproxy_form = AutoproxyLookupForm()

    autoproxy_infos = []
    if autoproxy_instance:
        ip_text = autoproxy_form.myip.data or ''
        url_text = autoproxy_form.url.data or ''
        url_text = url_text.strip()
        ip_text = ip_text.strip()
        if url_text:
            if ip_text and autoproxy_form.validate_on_submit():
                #logging.info('IP Address : {}'.format(ip_text))
                ip_list = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', ip_text)
                ip_list = drop_duplicates(ip_list)
                for ip_to_lookup in ip_list:
                    proxy = ""
                    try:
                        host, proxy = autoproxy_instance.lookup(url_text, ip_to_lookup)
                    except Exception as ex:
                        flash(f"Failed to lookup - {ex}")
                    if proxy:
                        autoproxy_info = {'IP': ip_to_lookup, 'Host': host, 'Proxy': proxy}
                        autoproxy_infos.append(autoproxy_info)

                if not autoproxy_infos:
                    flash("Could not find valid URL/IP  in the input")
    else:
        flash("No AutoProxy Module loaded: can not do lookups")

    return render_template('index.html', lookup_form=lookup_form, autoproxy_form=autoproxy_form, autoproxy_infos=autoproxy_infos, ipam_file=get_ipam_file(), start_ts=start_ts)
# ----------------------------------------------------------------------------------------------------------------------
