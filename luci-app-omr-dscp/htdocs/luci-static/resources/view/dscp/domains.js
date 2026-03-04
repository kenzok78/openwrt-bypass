'use strict';
'require view';
'require form';

return view.extend({
    render: function() {
	var m, s, hn, t, c;

	m = new form.Map('dscp', _('DSCP by domain'),
	    _('Set DSCP by domains.'));

	s = m.section(form.TableSection, 'domains', _('Domains'));
	s.addremove = true;
	s.anonymous = true;

	hn = s.option(form.Value, 'name', _('Domain'));
	hn.datatype = 'hostname';
	hn.optional = false;
	hn.rmempty = false;

	t = s.option(form.ListValue, 'class', _('Class'));
	t.value('cs0', _('CS0 - Normal/Best Effort'));
	t.value('cs1', _('CS1 - Low priority'));
	t.value('cs2', _('CS2 - High priority'));
	t.value('cs3', _('CS3 - SIP'));
	t.value('cs4', _('CS4 - Real-Time Interactive'));
	t.value('cs5', _('CS5 - Broadcast video'));
	t.value('cs6', _('CS6 - Network routing'));
	t.value('cs7', _('CS7 - Latency sensitive'));
	t.value('ef',  _('EF Voice'));

	c = s.option(form.Value, 'comment', _('Comment'));
	c.optional = true;
	c.rmempty = true;

	return m.render();
    }
});