\copy auth.users (id, name, email, created_at, updated_at) from stdin;
110	foorw	foorw@bar.com	2006-08-14	2006-08-14
111	hello	hello@bar.com	2006-08-14	2006-08-14
112	werr	werr@bar.com	2006-08-14	2006-08-14
113	wweddd	wweddd@bar.com	2006-08-14	2006-08-14
114	sdfdf	sdfdf@bar.com	2006-08-14	2006-08-14
115	sdfdaf	sdfdaf@bar.com	2006-08-14	2006-08-14
116	dsaf	dsaf@bar.com	2006-08-14	2006-08-14
117	dfsdf	dfsdf@bar.com	2006-08-14	2006-08-14
118	erfrwg	erfrwg@bar.com	2006-08-14	2006-08-14
\.

\copy auth.groups (id, name, created_at,	updated_at, description) from stdin;
124	adsssmi	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
123	whatsss	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
122	erfrwg	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
121	wwkn	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
120	zzzzzz	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
119	ddfggg	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
118	khkhkh	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
\.

\copy auth.audiences (id, name, created_at, updated_at, description) from stdin;
124	adsssmi	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
123	whatsss	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
122	erfrwg	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
121	wwkn	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
120	zzzzzz	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
119	ddfggg	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
118	khkhkh	2006-08-14	2006-08-14	Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna ali.
\.

\copy auth.user_groups (user_id, group_id) from stdin;
110	124
110	122
110	120
110	119
111	121
111	118
112	121
112	124
112	123
113	123
113	122
113	119
114	119
114	120
114	121
115	124
115	123
115	119
115	118
116	118
116	119
116	121
116	120
117	118
117	123
117	124
\.

\copy auth.user_audiences (user_id, audience_id) from stdin;
110	124
110	122
110	120
110	119
111	121
111	118
112	121
112	124
112	123
113	123
113	122
113	119
114	119
114	120
114	121
115	124
115	123
115	119
115	118
116	118
116	119
116	121
116	120
117	118
117	123
117	124
\.

\copy auth.passwords (user_id, salt, hash, created_at, updated_at) from stdin;
110	sssssss	xxxxxxxx	2006-08-14	2006-08-14
111	sssssss	xxxxxxxx	2006-08-14	2006-08-14
112	sssssss	xxxxxxxx	2006-08-14	2006-08-14
113	sssssss	xxxxxxxx	2006-08-14	2006-08-14
114	sssssss	xxxxxxxx	2006-08-14	2006-08-14
115	sssssss	xxxxxxxx	2006-08-14	2006-08-14
116	sssssss	xxxxxxxx	2006-08-14	2006-08-14
117	sssssss	xxxxxxxx	2006-08-14	2006-08-14
118	sssssss	xxxxxxxx	2006-08-14	2006-08-14
\.
