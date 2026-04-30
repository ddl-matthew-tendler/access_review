/* global React, ReactDOM, antd, dayjs, Highcharts, MOCK */
(function () {
  var ConfigProvider = antd.ConfigProvider;
  var Layout = antd.Layout;
  var Menu = antd.Menu;
  var Button = antd.Button;
  var Switch = antd.Switch;
  var Table = antd.Table;
  var Tag = antd.Tag;
  var Tooltip = antd.Tooltip;
  var Drawer = antd.Drawer;
  var Select = antd.Select;
  var Input = antd.Input;
  var InputNumber = antd.InputNumber;
  var AutoComplete = antd.AutoComplete;
  var message = antd.message;
  var Spin = antd.Spin;
  var Alert = antd.Alert;
  var Space = antd.Space;

  var h = React.createElement;
  var Fragment = React.Fragment;
  var useState = React.useState;
  var useEffect = React.useEffect;

  // ---- Role rendering (volumes + datasets) ---------------------------------
  // Use Domino's exact role names (Owner / Editor / Reader) so labels match
  // the Domino UI's Edit Volume / Edit Dataset Permissions panels. Tooltips
  // carry the explanation of what each role can do.
  var ROLE_META = {
    owner:  { label: 'Owner',  color: 'red',    tip: 'Full control: read, write, manage permissions, delete.' },
    editor: { label: 'Editor', color: 'orange', tip: 'Read and modify data. Cannot change permissions.' },
    reader: { label: 'Reader', color: 'blue',   tip: 'Read-only access.' },
    // Volume API returns "VolumeUser" for the lowest tier; Domino's UI shows
    // it as Reader. Treat as such.
    user:   { label: 'Reader', color: 'blue',   tip: 'Read-only access.' },
    // Legacy plumbing values — render the underlying Domino role anyway.
    'read/write': { label: 'Editor', color: 'orange', tip: 'Read and modify data.' },
    read:        { label: 'Reader', color: 'blue',   tip: 'Read-only access.' },
  };
  function roleKey(v) {
    if (!v) return null;
    // Strip Domino's resource-prefixed enum values: VolumeOwner, DatasetRwEditor, etc.
    return String(v).replace(/^(Volume|DatasetRw|Dataset|DataSource)/i, '').toLowerCase();
  }
  function permissionTag(v) {
    if (!v) return h('span', { className: 'text-muted' }, '—');
    var meta = ROLE_META[roleKey(v)];
    if (!meta) return h(Tag, null, v);
    return h(Tooltip, { title: meta.tip + ' (' + v + ')' }, h(Tag, { color: meta.color }, meta.label));
  }

  // Render the "Users and organizations" cell — single line with a small icon
  // prefix denoting User / Organization / Public / Project, matching Domino's
  // pattern where role grants are listed as "<icon> <name>".
  function principalCell(name, type) {
    var label = name || '—';
    var icon, color;
    if (type === 'Organization') { icon = '👥'; color = '#65657B'; }
    else if (type === 'Project')  { icon = '📁'; color = '#65657B'; }
    else if (type === 'Public')   { icon = '🌐'; color = '#C20A29'; }
    else                          { icon = '👤'; color = '#65657B'; }
    return h('span', null,
      h('span', { style: { marginRight: 6, color: color, fontSize: 12 } }, icon),
      h('span', null, label)
    );
  }

  // ---- Privileged-role explanations ---------------------------------------
  var PRIV_ROLE_TIPS = {
    SysAdmin:        'Full system administrator: install software, change global config, impersonate any user, manage all projects.',
    SystemAdministrator: 'Full system administrator (legacy name).',
    OrgAdmin:        'Manages an Organization\'s membership and resources. Cannot change global system config.',
    OrgOwner:        'Owns an Organization. Manages members and Org-level resources.',
    GovernanceAdmin: 'Manages governance bundles, policies, and review evidence. Cannot install software.',
    EnvironmentAdmin: 'Creates and manages compute environments and base images.',
    EnvAdmin:        'Creates and manages compute environments and base images.',
    LimitedAdmin:    'Restricted admin scope: project administration without full system rights.',
    SupportStaff:    'Read-only impersonation for support cases. Cannot make changes.',
    DataSourceAdmin: 'Manages data source connections (databases, S3, etc.). Cannot change global config.',
    Librarian:       'Curates featured projects, datasets, and templates.',
    ProjectManager:  'Project-level admin scope across multiple projects.',
    Practitioner:    'Standard user: can run workloads, create projects, no admin rights.',
  };
  function privilegedRoleTag(role) {
    var tip = PRIV_ROLE_TIPS[role] || 'Domino role: ' + role;
    return h(Tooltip, { key: role, title: tip },
      h(Tag, { color: 'red', style: { cursor: 'help' } }, role));
  }

  // ---- Sort + filter helpers used across every Table -----------------------
  // strSorter / dateSorter / numSorter return a (a,b)=>cmp using `key`.
  function strSorter(key) {
    return function (a, b) {
      return ((a && a[key]) || '').toString().localeCompare(((b && b[key]) || '').toString());
    };
  }
  function dateSorter(key) {
    return function (a, b) {
      var av = a && a[key]; var bv = b && b[key];
      return new Date(av || 0).getTime() - new Date(bv || 0).getTime();
    };
  }
  function numSorter(key) {
    return function (a, b) { return ((a && a[key]) || 0) - ((b && b[key]) || 0); };
  }
  // Build {filters, onFilter, filterSearch} from the unique values in `rows`
  // for the given `key`. Renders the cell value as the filter label by default.
  function dynamicFilters(rows, key, opts) {
    opts = opts || {};
    var seen = {};
    (rows || []).forEach(function (r) {
      var raw = r ? r[key] : null;
      var values = Array.isArray(raw) ? raw : [raw];
      values.forEach(function (v) {
        if (v == null || v === '') return;
        seen[v] = true;
      });
    });
    var values = Object.keys(seen).sort();
    return {
      filters: values.map(function (v) { return { text: opts.label ? opts.label(v) : v, value: v }; }),
      onFilter: function (value, record) {
        var v = record[key];
        return Array.isArray(v) ? v.indexOf(value) !== -1 : v === value;
      },
      filterSearch: true,
    };
  }
  var useMemo = React.useMemo;

  var dominoTheme = {
    token: {
      colorPrimary: '#543FDE',
      colorPrimaryHover: '#3B23D1',
      colorPrimaryActive: '#311EAE',
      colorText: '#2E2E38',
      colorTextSecondary: '#65657B',
      colorTextTertiary: '#8F8FA3',
      colorSuccess: '#28A464',
      colorWarning: '#CCB718',
      colorError: '#C20A29',
      colorInfo: '#0070CC',
      colorBgContainer: '#FFFFFF',
      colorBgLayout: '#FAFAFA',
      colorBorder: '#E0E0E0',
      fontFamily: 'Inter, Lato, Helvetica Neue, Helvetica, Arial, sans-serif',
      fontSize: 14,
      borderRadius: 4,
      borderRadiusLG: 8,
    },
    components: {
      Button: { primaryShadow: 'none', defaultShadow: 'none' },
      Table: { headerBg: '#FAFAFA', rowHoverBg: '#F5F5F5' },
    },
  };

  Highcharts.setOptions({
    colors: ['#543FDE', '#0070CC', '#28A464', '#CCB718', '#FF6543', '#E835A7', '#2EDCC4', '#A9734C'],
    chart: { style: { fontFamily: 'Inter, Lato, Helvetica Neue, Arial, sans-serif' } },
  });

  // ---- API helpers ---------------------------------------------------------
  // App is served behind Domino's proxy at /<projectId>/. Strip leading '/'
  // so fetches resolve relative to the current page, not the proxy root.
  function apiUrl(path) {
    return path.charAt(0) === '/' ? path.slice(1) : path;
  }
  function apiGet(path) {
    return fetch(apiUrl(path)).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }
  function apiPost(path) {
    return fetch(apiUrl(path), { method: 'POST' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }
  function apiPostJson(path, body) {
    return fetch(apiUrl(path), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  // ---- Reusable ------------------------------------------------------------
  function StatCard(props) {
    var cls = 'stat-card' + (props.onClick ? ' stat-card-clickable' : '') + (props.active ? ' stat-card-active' : '');
    return h('div', { className: cls, onClick: props.onClick || null },
      h('div', { className: 'stat-card-label' }, props.label),
      h('div', { className: 'stat-card-value ' + (props.color || '') }, props.value),
      props.sub ? h('div', { className: 'stat-card-sub' }, props.sub) : null
    );
  }

  function SnapshotBanner(props) {
    if (!props.snapshot) return null;
    var taken = props.snapshot.takenAt ? dayjs(props.snapshot.takenAt).format('YYYY-MM-DD HH:mm UTC') : '—';
    var label = props.live ? 'Live view' : 'Snapshot ' + (props.snapshot.id || '—');
    return h('span', { className: 'snapshot-banner' }, label, ' · ', taken);
  }

  function fmtDate(iso) {
    if (!iso) return h('span', { className: 'text-muted' }, '—');
    return dayjs(iso).format('YYYY-MM-DD');
  }

  function roleTag(role) {
    if (!role) return null;
    return h(Tag, { className: 'role-tag-' + role, bordered: true }, role);
  }

  function statusTag(status) {
    if (status === 'Disabled') return h(Tag, { color: 'red' }, 'Disabled');
    if (status === 'Active') return h(Tag, { color: 'green' }, 'Active');
    return h(Tag, null, status || '—');
  }

  function volumeTypeTag(t) {
    var color = t === 'Nfs' ? 'purple' : t === 'Smb' ? 'blue' : t === 'Efs' ? 'cyan' : 'default';
    var label = t === 'Nfs' ? 'NetApp / NFS' : (t || 'Generic');
    return h(Tag, { color: color }, label);
  }

  // ---- Pages ---------------------------------------------------------------

  function Dashboard(props) {
    var snap = props.snap;
    var counts = (snap && snap.counts) || {};
    var taken = snap && snap.takenAt ? dayjs(snap.takenAt).format('YYYY-MM-DD HH:mm UTC') : '—';
    var snapId = snap && snap.id ? snap.id : '—';
    var principal = snap && snap.principal ? (snap.principal.name || '—') : '—';

    return h('div', null,
      h('div', { className: 'attestation-banner' },
        h('div', null,
          h('div', { className: 'att-text' },
            'Reviewed snapshot ',
            h('strong', null, snapId),
            ' captured ',
            h('strong', null, taken),
            '. Scope: ',
            h('strong', null, (counts.users || 0) + ' users'), ', ',
            h('strong', null, (counts.privilegedUsers || 0) + ' administrators'), ', ',
            h('strong', null, (counts.projects || 0) + ' projects'), ', ',
            h('strong', null, (counts.datasets || 0) + ' datasets'), ', ',
            h('strong', null, (counts.dataSources || 0) + ' data sources'), ', ',
            h('strong', null, (counts.volumes || 0) + ' external volumes'), '.'
          ),
          h('div', { className: 'att-meta' },
            'Generated by ', principal, ' · paste this line into your access-review report.')
        )
      ),
      h('div', { className: 'stats-row' },
        h(StatCard, { label: 'Users', value: counts.users || 0, color: 'primary',
          onClick: function () { props.onNav('users'); } }),
        h(StatCard, { label: 'Administrators', value: counts.privilegedUsers || 0, color: 'danger',
          sub: 'SysAdmin / GovernanceAdmin / OrgAdmin / EnvironmentAdmin', onClick: function () { props.onNav('privileged'); } }),
        h(StatCard, { label: 'Projects', value: counts.projects || 0, color: 'info' }),
        h(StatCard, { label: 'Datasets', value: counts.datasets || 0,
          onClick: function () { props.onNav('datasets'); } }),
        h(StatCard, { label: 'Data sources', value: counts.dataSources || 0, color: 'info',
          sub: 'Snowflake / Redshift / S3 / etc.', onClick: function () { props.onNav('data-sources'); } }),
        h(StatCard, { label: 'External volumes', value: counts.volumes || 0, color: 'success',
          sub: 'NetApp / NFS / SMB / EFS', onClick: function () { props.onNav('volumes'); } })
      ),
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Periodic access review'),
            h('div', { className: 'panel-sub' }, 'GxP customers (Annex 11 §12 / GAMP 5 O8) typically review user access quarterly. Take a snapshot, sign it, archive the PDF.')
          ),
          h(Button, { type: 'primary', onClick: props.onTakeSnapshot, loading: props.takingSnapshot },
            'Take snapshot now')
        ),
        h('p', { style: { color: '#65657B', fontSize: 13, marginTop: 0, marginBottom: 0 } },
          'Each snapshot captures who has access to which projects, datasets, and external data volumes (NetApp / NFS / SMB / EFS) at this exact moment. Snapshots are immutable and exportable to PDF/CSV for auditor delivery.')
      )
    );
  }

  function AccessListingPage(props) {
    var rows = props.rows || [];
    var _f = useState({ search: '', role: null, status: null });
    var f = _f[0]; var setF = _f[1];

    var roles = useMemo(function () {
      var s = {}; rows.forEach(function (r) { if (r.role) s[r.role] = true; });
      return Object.keys(s).sort();
    }, [rows]);

    var filtered = useMemo(function () {
      var q = (f.search || '').toLowerCase();
      return rows.filter(function (r) {
        if (f.role && r.role !== f.role) return false;
        if (f.status && r.status !== f.status) return false;
        if (q) {
          var hay = ((r.userName || '') + ' ' + (r.email || '') + ' ' + (r.projectName || '') + ' ' + (r.fullName || '')).toLowerCase();
          if (hay.indexOf(q) === -1) return false;
        }
        return true;
      });
    }, [rows, f]);

    var columns = [
      Object.assign({ title: 'User', dataIndex: 'userName', key: 'userName', width: 160, fixed: 'left',
        sorter: strSorter('userName'),
        render: function (v, r) {
          return h('div', null,
            h('div', { style: { fontWeight: 500 } }, v || '—'),
            r.fullName ? h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, r.fullName) : null
          );
        }
      }, dynamicFilters(rows, 'userName')),
      Object.assign({ title: 'Email', dataIndex: 'email', key: 'email', width: 220, ellipsis: true,
        sorter: strSorter('email'),
        render: function (v) { return v ? h(Tooltip, { title: v }, v) : h('span', { className: 'text-muted' }, '—'); } },
        dynamicFilters(rows, 'email')),
      Object.assign({ title: 'Project', dataIndex: 'projectName', key: 'projectName', width: 220, ellipsis: true,
        sorter: strSorter('projectName') },
        dynamicFilters(rows, 'projectName')),
      Object.assign({ title: 'Role', dataIndex: 'role', key: 'role', width: 140,
        sorter: strSorter('role'),
        render: function (v) { return roleTag(v); } },
        dynamicFilters(rows, 'role')),
      Object.assign({ title: 'Status', dataIndex: 'status', key: 'status', width: 100,
        sorter: strSorter('status'),
        render: function (v) { return statusTag(v); } },
        dynamicFilters(rows, 'status')),
      { title: 'User type', dataIndex: 'userType', key: 'userType', width: 130,
        sorter: strSorter('userType'),
        filters: [
          { text: 'Human', value: 'human' },
          { text: 'Service account', value: 'service_account' },
          { text: 'Domino employee', value: 'domino_employee' },
          { text: 'Organization', value: 'organization' },
        ],
        defaultFilteredValue: ['human'],
        onFilter: function (value, record) { return record.userType === value; },
        render: function (v) { return v ? v.replace(/_/g, ' ') : '—'; } },
      { title: 'Last workload', dataIndex: 'lastWorkload', key: 'lastWorkload', width: 150,
        sorter: dateSorter('lastWorkload'),
        render: function (v) {
          if (!v) return h('span', { className: 'text-muted' }, '—');
          return h(Tooltip, { title: v }, dayjs(v).format('YYYY-MM-DD'));
        } },
      { title: 'Granted', dataIndex: 'grantedAt', key: 'grantedAt', width: 110,
        sorter: dateSorter('grantedAt'),
        render: function (v) { return v ? fmtDate(v) : h('span', { className: 'text-muted' }, '—'); } },
      Object.assign({ title: 'Granted by', dataIndex: 'grantedBy', key: 'grantedBy', width: 140,
        sorter: strSorter('grantedBy'),
        render: function (v) { return v || h('span', { className: 'text-muted' }, '—'); } },
        dynamicFilters(rows, 'grantedBy')),
    ];

    return h('div', null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'User access listing'),
            h('div', { className: 'panel-sub' }, filtered.length + ' of ' + rows.length + ' rows · User × Project × Role')
          ),
          h(Space, null,
            h(Input.Search, { placeholder: 'Search user, email, project',
              allowClear: true, style: { width: 280 },
              onSearch: function (v) { setF(Object.assign({}, f, { search: v })); },
              onChange: function (e) { setF(Object.assign({}, f, { search: e.target.value })); } }),
            h(Select, { placeholder: 'Role', allowClear: true, style: { width: 150 },
              value: f.role, onChange: function (v) { setF(Object.assign({}, f, { role: v })); },
              options: roles.map(function (r) { return { label: r, value: r }; }) }),
            h(Select, { placeholder: 'Status', allowClear: true, style: { width: 130 },
              value: f.status, onChange: function (v) { setF(Object.assign({}, f, { status: v })); },
              options: [{ label: 'Active', value: 'Active' }, { label: 'Disabled', value: 'Disabled' }] }),
            h(Button, { onClick: function () { props.onExport('access-listing', 'csv'); } }, 'Export CSV'),
            h(Button, { onClick: function () { props.onExport('access-listing', 'pdf'); } }, 'Export PDF')
          )
        ),
        h(Table, {
          dataSource: filtered, columns: columns, rowKey: function (r) { return r.userId + '|' + r.projectId; },
          size: 'small', pagination: { pageSize: 25, showSizeChanger: true },
          scroll: { x: 1100 },
          rowClassName: function (r) { return r.status === 'Disabled' ? 'row-disabled-user' : ''; }
        })
      )
    );
  }

  function PrivilegedPage(props) {
    var rows = props.rows || [];
    var columns = [
      Object.assign({ title: 'User', dataIndex: 'userName', key: 'userName', width: 160,
        sorter: strSorter('userName'), defaultSortOrder: 'ascend',
        render: function (v, r) {
          return h('div', null,
            h('div', { style: { fontWeight: 500 } }, v || '—'),
            r.fullName ? h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, r.fullName) : null
          );
        }
      }, dynamicFilters(rows, 'userName')),
      Object.assign({ title: 'Email', dataIndex: 'email', key: 'email', width: 220, ellipsis: true,
        sorter: strSorter('email') },
        dynamicFilters(rows, 'email')),
      Object.assign({ title: 'Roles', dataIndex: 'roles', key: 'roles', width: 320,
        render: function (rs) {
          if (!rs || !rs.length) return h('span', { className: 'text-muted' }, '—');
          return rs.map(privilegedRoleTag);
        }
      }, dynamicFilters(rows, 'roles')),
      Object.assign({ title: 'Status', dataIndex: 'status', key: 'status', width: 100,
        sorter: strSorter('status'), render: statusTag },
        dynamicFilters(rows, 'status')),
      { title: 'Last workload', dataIndex: 'lastWorkload', key: 'lastWorkload', width: 160,
        sorter: dateSorter('lastWorkload'),
        render: function (v) {
          if (!v) return h('span', { className: 'text-muted' }, '—');
          return h(Tooltip, { title: v }, dayjs(v).format('YYYY-MM-DD HH:mm'));
        }
      },
    ];

    return h('div', { className: 'panel' },
      h('div', { className: 'panel-header' },
        h('div', null,
          h('div', { className: 'panel-title' }, 'Administrators'),
          h('div', { className: 'panel-sub' }, rows.length + ' users with administrative roles · review quarterly per GAMP 5 O8')
        ),
        h(Space, null,
          h(Button, { onClick: function () { props.onExport('privileged', 'csv'); } }, 'Export CSV'),
          h(Button, { onClick: function () { props.onExport('privileged', 'pdf'); } }, 'Export PDF')
        )
      ),
      rows.length === 0
        ? h('div', { className: 'empty-state' },
            h('div', { className: 'empty-state-title' }, 'No administrators found'),
            h('div', { className: 'empty-state-body' }, 'Either nobody holds an admin role, or the service account lacks visibility. Confirm the API_KEY_OVERRIDE has admin scope.'))
        : h(Table, { dataSource: rows, columns: columns, rowKey: 'userId', size: 'small',
            pagination: { pageSize: 25 } })
    );
  }

  function VolumesPage(props) {
    var rows = props.rows || [];
    var _f = useState({ type: null, search: '' });
    var f = _f[0]; var setF = _f[1];

    var filtered = useMemo(function () {
      var q = (f.search || '').toLowerCase();
      return rows.filter(function (r) {
        if (f.type && r.volumeType !== f.type) return false;
        if (q) {
          var hay = ((r.volumeName || '') + ' ' + (r.principalName || '') + ' ' + (r.mountPath || '')).toLowerCase();
          if (hay.indexOf(q) === -1) return false;
        }
        return true;
      });
    }, [rows, f]);

    var stats = useMemo(function () {
      var byType = {};
      var pubCount = 0;
      var rwCount = 0;
      rows.forEach(function (r) {
        byType[r.volumeType] = (byType[r.volumeType] || 0) + 1;
        if (r.principalType === 'Public') pubCount += 1;
        if (r.permission === 'read/write') rwCount += 1;
      });
      return { byType: byType, pubCount: pubCount, rwCount: rwCount };
    }, [rows]);

    var columns = [
      Object.assign({ title: 'Volume', dataIndex: 'volumeName', key: 'volumeName', width: 220,
        sorter: strSorter('volumeName'),
        render: function (v, r) {
          return h('div', null,
            h('div', { style: { fontWeight: 500 } }, v),
            h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, r.mountPath));
        } }, dynamicFilters(rows, 'volumeName')),
      { title: 'Type', dataIndex: 'volumeType', key: 'volumeType', width: 130,
        sorter: strSorter('volumeType'),
        filters: [{text:'NetApp / NFS', value:'Nfs'}, {text:'SMB', value:'Smb'}, {text:'EFS', value:'Efs'}, {text:'Generic', value:'Generic'}],
        onFilter: function (v, r) { return r.volumeType === v; },
        render: volumeTypeTag },
      Object.assign({ title: 'Users and organizations', dataIndex: 'principalName', key: 'pName',
        width: 280, ellipsis: true,
        sorter: strSorter('principalName'),
        render: function (v, r) { return principalCell(v, r.principalType); }
      }, dynamicFilters(rows, 'principalName')),
      Object.assign({ title: 'Role', dataIndex: 'permission', key: 'perm', width: 130,
        sorter: strSorter('permission'),
        render: permissionTag }, dynamicFilters(rows, 'permission')),
      Object.assign({ title: 'Granted via', dataIndex: 'via', key: 'via', width: 160,
        sorter: strSorter('via'),
        render: function (v) { return h('span', { style: { fontSize: 12, color: '#65657B' } }, v); } },
        dynamicFilters(rows, 'via')),
      { title: 'Granted at', dataIndex: 'grantedAt', key: 'grantedAt', width: 130,
        sorter: dateSorter('grantedAt'),
        render: function (v) { return v ? fmtDate(v) : h('span', { className: 'text-muted' }, '—'); } },
      Object.assign({ title: 'Granted by', dataIndex: 'grantedBy', key: 'grantedBy', width: 150,
        sorter: strSorter('grantedBy'),
        render: function (v) { return v || h('span', { className: 'text-muted' }, '—'); } },
        dynamicFilters(rows, 'grantedBy')),
    ];

    return h('div', null,
      h('div', { className: 'stats-row' },
        h(StatCard, { label: 'NetApp / NFS rows', value: stats.byType.Nfs || 0, color: 'primary' }),
        h(StatCard, { label: 'SMB rows', value: stats.byType.Smb || 0, color: 'info' }),
        h(StatCard, { label: 'EFS rows', value: stats.byType.Efs || 0 }),
        h(StatCard, { label: 'Public-mounted', value: stats.pubCount, color: 'danger', sub: 'isPublic = true' }),
        h(StatCard, { label: 'Read/write grants', value: stats.rwCount, color: 'warning' })
      ),
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'External data volume access'),
            h('div', { className: 'panel-sub' }, filtered.length + ' of ' + rows.length + ' grants · NetApp / NFS / SMB / EFS via /remotefs/v1')
          ),
          h(Space, null,
            h(Input.Search, { placeholder: 'Search volume, mount, principal',
              allowClear: true, style: { width: 280 },
              onChange: function (e) { setF(Object.assign({}, f, { search: e.target.value })); } }),
            h(Select, { placeholder: 'Volume type', allowClear: true, style: { width: 150 },
              value: f.type, onChange: function (v) { setF(Object.assign({}, f, { type: v })); },
              options: [
                { label: 'NetApp / NFS', value: 'Nfs' },
                { label: 'SMB', value: 'Smb' },
                { label: 'EFS', value: 'Efs' },
                { label: 'Generic', value: 'Generic' },
              ] }),
            h(Button, { onClick: function () { props.onExport('volumes', 'csv'); } }, 'Export CSV'),
            h(Button, { onClick: function () { props.onExport('volumes', 'pdf'); } }, 'Export PDF')
          )
        ),
        h(Table, {
          dataSource: filtered, columns: columns, size: 'small',
          rowKey: function (r) { return r.volumeId + '|' + r.principalType + '|' + (r.principalId || 'public'); },
          pagination: { pageSize: 25 }
        })
      )
    );
  }

  function DatasetsPage(props) {
    var rows = props.rows || [];
    var _f = useState({ search: '' });
    var f = _f[0]; var setF = _f[1];
    var filtered = useMemo(function () {
      var q = (f.search || '').toLowerCase();
      return rows.filter(function (r) {
        if (!q) return true;
        var hay = ((r.datasetName || '') + ' ' + (r.projectName || '') + ' ' + (r.principalName || '')).toLowerCase();
        return hay.indexOf(q) !== -1;
      });
    }, [rows, f]);

    var columns = [
      Object.assign({ title: 'Dataset', dataIndex: 'datasetName', key: 'd', width: 220,
        sorter: strSorter('datasetName') }, dynamicFilters(rows, 'datasetName')),
      Object.assign({ title: 'Project', dataIndex: 'projectName', key: 'p', width: 200,
        sorter: strSorter('projectName') }, dynamicFilters(rows, 'projectName')),
      Object.assign({ title: 'Users and organizations', dataIndex: 'principalName', key: 'pn',
        width: 280, ellipsis: true,
        sorter: strSorter('principalName'),
        render: function (v, r) { return principalCell(v, r.principalType); }
      }, dynamicFilters(rows, 'principalName')),
      Object.assign({ title: 'Role', dataIndex: 'permission', key: 'perm', width: 130,
        sorter: strSorter('permission'), render: permissionTag },
        dynamicFilters(rows, 'permission')),
      { title: 'Granted at', dataIndex: 'grantedAt', key: 'ga', width: 130,
        sorter: dateSorter('grantedAt'),
        render: function (v) { return v ? fmtDate(v) : h('span', { className: 'text-muted' }, '—'); } },
      Object.assign({ title: 'Granted by', dataIndex: 'grantedBy', key: 'gb', width: 150,
        sorter: strSorter('grantedBy'),
        render: function (v) { return v || h('span', { className: 'text-muted' }, '—'); } },
        dynamicFilters(rows, 'grantedBy')),
    ];
    return h('div', null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Dataset access'),
            h('div', { className: 'panel-sub' }, filtered.length + ' of ' + rows.length + ' grants · /api/datasetrw/v1')
          ),
          h(Space, null,
            h(Input.Search, { placeholder: 'Search dataset, project, principal',
              allowClear: true, style: { width: 280 },
              onChange: function (e) { setF({ search: e.target.value }); } }),
            h(Button, { onClick: function () { props.onExport('datasets', 'csv'); } }, 'Export CSV'),
            h(Button, { onClick: function () { props.onExport('datasets', 'pdf'); } }, 'Export PDF')
          )
        ),
        h(Table, {
          dataSource: filtered, columns: columns, size: 'small',
          rowKey: function (r) { return r.datasetId + '|' + r.principalType + '|' + (r.principalId || 'public'); },
          pagination: { pageSize: 25, showSizeChanger: true }
        })
      )
    );
  }

  function DataSourcesPage(props) {
    var rows = props.rows || [];
    var _f = useState({ search: '' });
    var f = _f[0]; var setF = _f[1];
    var filtered = useMemo(function () {
      var q = (f.search || '').toLowerCase();
      return rows.filter(function (r) {
        if (!q) return true;
        var hay = ((r.dataSourceName || '') + ' ' + (r.principalName || '') + ' ' + (r.dataSourceType || '')).toLowerCase();
        return hay.indexOf(q) !== -1;
      });
    }, [rows, f]);

    var columns = [
      Object.assign({ title: 'Data source', dataIndex: 'dataSourceName', key: 'd', width: 220,
        sorter: strSorter('dataSourceName'),
        render: function (v, r) {
          return h('div', null,
            h('div', { style: { fontWeight: 500 } }, v),
            r.authType ? h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, r.authType) : null);
        } }, dynamicFilters(rows, 'dataSourceName')),
      Object.assign({ title: 'Type', dataIndex: 'dataSourceType', key: 't', width: 130,
        sorter: strSorter('dataSourceType'),
        render: function (v) { return v ? h(Tag, { color: 'purple' }, v) : '—'; } },
        dynamicFilters(rows, 'dataSourceType')),
      Object.assign({ title: 'Credential', dataIndex: 'credentialType', key: 'c', width: 130,
        sorter: strSorter('credentialType'),
        render: function (v) {
          if (!v) return h('span', { className: 'text-muted' }, '—');
          var tip = v === 'Shared'
            ? 'All authorized users connect with the same shared credentials. Auditor flag: identifies a shared service-account password.'
            : 'Each user provides their own credentials.';
          return h(Tooltip, { title: tip },
            h(Tag, { color: v === 'Shared' ? 'orange' : 'green' }, v));
        } }, dynamicFilters(rows, 'credentialType')),
      Object.assign({ title: 'Users and organizations', dataIndex: 'principalName', key: 'pn',
        width: 280, ellipsis: true,
        sorter: strSorter('principalName'),
        render: function (v, r) { return principalCell(v, r.principalType); }
      }, dynamicFilters(rows, 'principalName')),
      Object.assign({ title: 'Role', dataIndex: 'permission', key: 'perm', width: 130,
        sorter: strSorter('permission'),
        render: function (v) {
          if (!v) return h('span', { className: 'text-muted' }, '—');
          // Data sources have only Owner / authorized-user. Map User->Authorized.
          if (/Owner$/i.test(v)) {
            return h(Tooltip, { title: 'Owner of this data source. Can manage configuration and permissions. (' + v + ')' },
              h(Tag, { color: 'red' }, 'Owner'));
          }
          return h(Tooltip, { title: 'Authorized to use this data source connection. (' + v + ')' },
            h(Tag, { color: 'blue' }, 'Authorized'));
        } }, dynamicFilters(rows, 'permission')),
      Object.assign({ title: 'Status', dataIndex: 'status', key: 'st', width: 100,
        sorter: strSorter('status'),
        render: function (v) { return v ? h(Tag, { color: v === 'Active' ? 'green' : 'default' }, v) : '—'; } },
        dynamicFilters(rows, 'status')),
    ];
    return h('div', null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Data source access'),
            h('div', { className: 'panel-sub' }, filtered.length + ' of ' + rows.length + ' grants · Snowflake / Redshift / S3 / etc. via /datasource')
          ),
          h(Space, null,
            h(Input.Search, { placeholder: 'Search data source, type, principal',
              allowClear: true, style: { width: 280 },
              onChange: function (e) { setF({ search: e.target.value }); } }),
            h(Button, { onClick: function () { props.onExport('data-sources', 'csv'); } }, 'Export CSV'),
            h(Button, { onClick: function () { props.onExport('data-sources', 'pdf'); } }, 'Export PDF')
          )
        ),
        h(Table, {
          dataSource: filtered, columns: columns, size: 'small',
          rowKey: function (r) { return r.dataSourceId + '|' + r.principalType + '|' + (r.principalId || 'public'); },
          pagination: { pageSize: 25, showSizeChanger: true }
        })
      )
    );
  }

  function VerifyUserPage(props) {
    var _u = useState(''); var userName = _u[0]; var setUserName = _u[1];
    var _data = useState(null); var data = _data[0]; var setData = _data[1];
    var _loading = useState(false); var loading = _loading[0]; var setLoading = _loading[1];
    var _gt = useState({ expectedProjects: '', expectedRoles: '', expectedVolumes: '' });
    var gt = _gt[0]; var setGt = _gt[1];
    var _rec = useState(null); var rec = _rec[0]; var setRec = _rec[1];
    var _users = useState([]); var allUsers = _users[0]; var setAllUsers = _users[1];

    useEffect(function () {
      apiGet('/api/users-lookup').then(function (rows) {
        setAllUsers(rows || []);
      }).catch(function () { /* fall back to free-text input */ });
    }, []);

    var options = useMemo(function () {
      var q = (userName || '').trim().toLowerCase();
      var matches = allUsers.filter(function (u) {
        if (!q) return true;
        var hay = ((u.userName || '') + ' ' + (u.fullName || '') + ' ' + (u.email || '')).toLowerCase();
        return hay.indexOf(q) !== -1;
      }).slice(0, 50);
      return matches.map(function (u) {
        var typeLabel = u.userType ? u.userType.replace(/_/g, ' ') : 'human';
        return {
          value: u.userName,
          label: h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } },
            h('div', null,
              h('div', { style: { fontWeight: 500 } }, u.userName || '—'),
              u.fullName ? h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, u.fullName) : null
            ),
            h(Tag, { style: { fontSize: 10 }, color: u.userType === 'human' ? 'blue' : u.userType === 'organization' ? 'purple' : 'default' }, typeLabel)
          ),
        };
      });
    }, [allUsers, userName]);

    function lookup() {
      if (!userName.trim()) return;
      setLoading(true); setRec(null);
      apiGet('/api/verify/user/' + encodeURIComponent(userName.trim()))
        .then(setData).catch(function (e) { message.error(e.message); setData(null); })
        .finally(function () { setLoading(false); });
    }

    function runReconcile() {
      var payload = { userName: userName.trim() };
      try {
        if (gt.expectedProjects.trim()) {
          payload.expectedProjects = gt.expectedProjects.trim().split('\n').map(function (l) {
            var parts = l.split('|').map(function (s) { return s.trim(); });
            return { projectName: parts[0], role: parts[1] || null };
          }).filter(function (e) { return e.projectName; });
        }
        if (gt.expectedRoles.trim()) {
          payload.expectedRoles = gt.expectedRoles.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
        }
        if (gt.expectedVolumes.trim()) {
          payload.expectedVolumes = gt.expectedVolumes.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
        }
      } catch (e) { message.error('Could not parse ground truth: ' + e.message); return; }
      fetch(apiUrl('/api/verify/reconcile'), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }).then(function (r) { return r.json(); }).then(setRec)
        .catch(function (e) { message.error(e.message); });
    }

    var projectCols = [
      { title: 'Project', dataIndex: 'projectName', key: 'p', ellipsis: true },
      { title: 'Role at this moment', dataIndex: 'role', key: 'r', width: 180,
        render: function (v) { return roleTag(v); } },
      { title: 'Granted', dataIndex: 'grantedAt', key: 'g', width: 130, render: fmtDate },
    ];
    var dsCols = [
      { title: 'Dataset', dataIndex: 'datasetName', key: 'd', ellipsis: true },
      { title: 'Access', dataIndex: 'permission', key: 'p', width: 150, render: permissionTag },
      { title: 'Source', dataIndex: 'source', key: 's', width: 180, render: function (v) { return h('span', { style: { fontSize: 11, color: '#65657B' } }, v || '—'); } },
    ];
    var volCols = [
      { title: 'Volume', dataIndex: 'volumeName', key: 'v', ellipsis: true },
      { title: 'Type', dataIndex: 'volumeType', key: 't', width: 130, render: volumeTypeTag },
      { title: 'Access', dataIndex: 'permission', key: 'p', width: 150, render: permissionTag },
    ];

    return h('div', null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Verify a user'),
            h('div', { className: 'panel-sub' }, 'Spot-check what one user can access at this exact moment — projects + role, datasets, NetApp volumes')
          )
        ),
        h(Space, null,
          h(AutoComplete, {
            value: userName,
            options: options,
            onChange: function (v) { setUserName(v || ''); },
            onSelect: function (v) { setUserName(v); setTimeout(lookup, 0); },
            onKeyDown: function (e) { if (e.key === 'Enter') lookup(); },
            placeholder: 'Start typing a username (e.g. matt)',
            style: { width: 420 },
            allowClear: true,
            popupMatchSelectWidth: 480,
            filterOption: false,
            defaultOpen: false,
          }),
          h(Button, { type: 'primary', onClick: lookup, loading: loading }, 'Look up user')
        )
      ),
      data ? h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, data.user.fullName + ' (' + data.user.userName + ')'),
            h('div', { className: 'panel-sub' }, data.user.email + ' · ' + (data.user.licenseType || '—') + ' · ' + (data.user.status || '—'))
          ),
          h(Space, null,
            data.isPrivileged ? h(Tag, { color: 'red' }, 'Administrator') : null,
            (data.globalRoles || []).map(function (r) { return h(Tag, { key: r, color: 'purple' }, r); })
          )
        ),
        h('div', { className: 'stats-row' },
          h(StatCard, { label: 'Projects', value: data.summary.projectCount, color: 'primary' }),
          h(StatCard, { label: 'Datasets', value: data.summary.datasetCount, color: 'info' }),
          h(StatCard, { label: 'Volumes', value: data.summary.volumeCount, color: 'success' })
        ),
        h('div', { className: 'panel-title', style: { marginTop: 8 } }, 'Project memberships'),
        h(Table, { dataSource: data.projectMemberships, columns: projectCols, size: 'small', rowKey: 'projectId', pagination: false }),
        h('div', { className: 'panel-title', style: { marginTop: 16 } }, 'Dataset grants'),
        h(Table, { dataSource: data.datasetGrants, columns: dsCols, size: 'small', rowKey: 'datasetId', pagination: false }),
        h('div', { className: 'panel-title', style: { marginTop: 16 } }, 'NetApp volume access'),
        h(Table, { dataSource: data.volumeAccess, columns: volCols, size: 'small', rowKey: 'volumeId', pagination: false })
      ) : null,
      data ? h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Reconcile against ground truth'),
            h('div', { className: 'panel-sub' }, 'Paste your expected access — we mark each row pass/fail')
          )
        ),
        h(Space, { direction: 'vertical', style: { width: '100%' } },
          h('div', null,
            h('div', { style: { fontSize: 12, color: '#65657B', marginBottom: 4 } }, 'Expected projects (one per line: "name | role")'),
            h(Input.TextArea, { rows: 4, value: gt.expectedProjects,
              placeholder: 'supply_risk_radar | Owner\nbiomarker_forge | Owner',
              onChange: function (e) { setGt(Object.assign({}, gt, { expectedProjects: e.target.value })); } })
          ),
          h('div', null,
            h('div', { style: { fontSize: 12, color: '#65657B', marginBottom: 4 } }, 'Expected global roles (comma-separated)'),
            h(Input, { value: gt.expectedRoles, placeholder: 'SysAdmin, Practitioner',
              onChange: function (e) { setGt(Object.assign({}, gt, { expectedRoles: e.target.value })); } })
          ),
          h('div', null,
            h('div', { style: { fontSize: 12, color: '#65657B', marginBottom: 4 } }, 'Expected NetApp volumes (comma-separated)'),
            h(Input, { value: gt.expectedVolumes, placeholder: 'NetApp_App, skill-test-volume',
              onChange: function (e) { setGt(Object.assign({}, gt, { expectedVolumes: e.target.value })); } })
          ),
          h(Button, { type: 'primary', onClick: runReconcile }, 'Run reconciliation')
        ),
        rec ? h('div', { style: { marginTop: 16 } },
          h(Alert, {
            type: rec.summary.allPass ? 'success' : 'warning',
            showIcon: true,
            message: rec.summary.allPass
              ? 'All expectations matched'
              : 'Reconciliation summary — see details below',
            description: 'Projects: ' + rec.summary.projectsPass + '/' + rec.summary.projectsTotal +
              ' · Roles: ' + rec.summary.rolesPass + '/' + rec.summary.rolesTotal +
              ' · Volumes: ' + rec.summary.volumesPass + '/' + rec.summary.volumesTotal,
            style: { marginBottom: 12 },
          }),
          rec.findings.projects.length ? h(Table, {
            title: function () { return 'Project findings'; },
            dataSource: rec.findings.projects, size: 'small', pagination: false,
            rowKey: 'projectName', columns: [
              { title: 'Project', dataIndex: 'projectName' },
              { title: 'Expected', dataIndex: 'expectedRole', width: 140 },
              { title: 'Actual', dataIndex: 'actualRole', width: 140 },
              { title: 'Pass', dataIndex: 'pass', width: 80,
                render: function (v) { return v ? h(Tag, { color: 'green' }, '✓') : h(Tag, { color: 'red' }, '✗'); } },
            ]}) : null,
          rec.findings.roles.length ? h(Table, {
            title: function () { return 'Global role findings'; },
            dataSource: rec.findings.roles, size: 'small', pagination: false,
            rowKey: 'role', columns: [
              { title: 'Role', dataIndex: 'role' },
              { title: 'Pass', dataIndex: 'pass', width: 80,
                render: function (v) { return v ? h(Tag, { color: 'green' }, '✓') : h(Tag, { color: 'red' }, '✗'); } },
            ]}) : null,
          rec.findings.volumes.length ? h(Table, {
            title: function () { return 'Volume findings'; },
            dataSource: rec.findings.volumes, size: 'small', pagination: false,
            rowKey: 'volumeName', columns: [
              { title: 'Volume', dataIndex: 'volumeName' },
              { title: 'Pass', dataIndex: 'pass', width: 80,
                render: function (v) { return v ? h(Tag, { color: 'green' }, '✓') : h(Tag, { color: 'red' }, '✗'); } },
            ]}) : null
        ) : null
      ) : null
    );
  }

  function DebugPage(props) {
    var _d = useState(null); var data = _d[0]; var setData = _d[1];
    var _l = useState(false); var loading = _l[0]; var setLoading = _l[1];

    function refresh() {
      setLoading(true);
      apiGet('/api/debug').then(setData).catch(function (e) { message.error(e.message); })
        .finally(function () { setLoading(false); });
    }
    useEffect(function () { refresh(); }, []);

    if (loading || !data) return h(Spin, { style: { display: 'block', margin: '60px auto' } });

    var ep = data.endpoints || {};
    function epCard(key, ok, body) {
      return h('div', { key: key, className: 'panel', style: { marginBottom: 12 } },
        h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } },
          h('div', null,
            h('strong', null, key),
            h('div', { style: { fontSize: 11, color: '#8F8FA3' } }, body.path || '')
          ),
          ok ? h(Tag, { color: 'green' }, '✓ OK') : h(Tag, { color: 'orange' }, '⚠ partial')
        ),
        body.note ? h('div', { style: { fontSize: 11, color: '#65657B', marginTop: 4 } }, body.note) : null,
        body.count != null ? h('div', { style: { fontSize: 11, color: '#65657B', marginTop: 2 } }, 'rows returned: ' + body.count) : null,
        body.sampleCount != null ? h('div', { style: { fontSize: 11, color: '#65657B', marginTop: 2 } }, 'sample fetched: ' + body.sampleCount + ' events') : null
      );
    }

    var top = data.lastSnapshot && data.lastSnapshot.projectionSummary || {};
    var counts = (top.eventCounts) || {};
    var sortedCounts = Object.keys(counts).map(function (k) { return [k, counts[k]]; })
      .sort(function (a, b) { return b[1] - a[1]; });

    return h('div', null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Identity & connectivity'),
            h('div', { className: 'panel-sub' }, data.host)
          ),
          h(Button, { onClick: refresh, size: 'small' }, 'Refresh')
        ),
        h('div', null,
          h('div', null, h('strong', null, 'Calling principal: '),
            data.principal && data.principal.name,
            data.principal && data.principal.isAdmin ? h(Tag, { color: 'red', style: { marginLeft: 8 } }, 'isAdmin: true') : null),
          h('div', { style: { fontSize: 12, color: '#65657B', marginTop: 4 } },
            'Self-roles (from /v4/users/self): ',
            (data.principal && data.principal.selfRoles && data.principal.selfRoles.length)
              ? data.principal.selfRoles.join(', ')
              : '(none — limited to org-Admin and audit-projected roles)')
        )
      ),
      h('div', { className: 'panel' },
        h('div', { className: 'panel-title' }, 'Endpoint coverage'),
        epCard('users', ep.users && ep.users.ok, ep.users || {}),
        epCard('projects', ep.projects && ep.projects.ok, ep.projects || {}),
        epCard('datamount', ep.datamount && ep.datamount.count > 0, ep.datamount || {}),
        epCard('audit', ep.audit && ep.audit.ok, ep.audit || {}),
        epCard('datasetGrants', true, ep.datasetGrants || {})
      ),
      data.lastSnapshot ? h('div', { className: 'panel' },
        h('div', { className: 'panel-title' }, 'Last snapshot · ' + data.lastSnapshot.id),
        h('div', { className: 'panel-sub' }, dayjs(data.lastSnapshot.takenAt).format('YYYY-MM-DD HH:mm UTC')),
        h('div', { className: 'stats-row', style: { marginTop: 12 } },
          h(StatCard, { label: 'Users', value: data.lastSnapshot.counts.users }),
          h(StatCard, { label: 'Projects', value: data.lastSnapshot.counts.projects }),
          h(StatCard, { label: 'Datasets', value: data.lastSnapshot.counts.datasets }),
          h(StatCard, { label: 'Volumes', value: data.lastSnapshot.counts.volumes }),
          h(StatCard, { label: 'Audit events replayed', value: top.totalEvents || 0, color: 'primary' }),
          h(StatCard, { label: 'Volumes via audit only', value: top.discoveredVolumeCount || 0, color: 'warning' })
        )
      ) : null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-title' }, 'Audit event types replayed (top 30)'),
        h(Table, {
          size: 'small', pagination: false,
          dataSource: sortedCounts.slice(0, 30).map(function (e) { return { name: e[0], count: e[1] }; }),
          rowKey: 'name',
          columns: [
            { title: 'Event', dataIndex: 'name' },
            { title: 'Count', dataIndex: 'count', width: 100, align: 'right' },
          ],
        })
      )
    );
  }

  function SnapshotsPage(props) {
    var snaps = props.snaps || [];
    var columns = [
      { title: 'Snapshot ID', dataIndex: 'id', key: 'id', width: 280,
        render: function (v) { return h('code', { style: { fontSize: 12 } }, v); } },
      { title: 'Taken', dataIndex: 'takenAt', key: 'takenAt', width: 200,
        render: function (v) { return v ? dayjs(v).format('YYYY-MM-DD HH:mm UTC') : '—'; } },
      { title: 'By', dataIndex: 'takenBy', key: 'by', width: 140 },
      { title: 'Users', dataIndex: ['counts', 'users'], key: 'u', align: 'right', width: 90 },
      { title: 'Projects', dataIndex: ['counts', 'projects'], key: 'p', align: 'right', width: 90 },
      { title: 'Datasets', dataIndex: ['counts', 'datasets'], key: 'd', align: 'right', width: 90 },
      { title: 'Volumes', dataIndex: ['counts', 'volumes'], key: 'v', align: 'right', width: 90 },
      { title: 'Administrators', dataIndex: ['counts', 'privilegedUsers'], key: 'pr', align: 'right', width: 130 },
      { title: 'Signed', dataIndex: 'signed', key: 'signed', width: 90,
        render: function (v) { return v ? h(Tag, { color: 'green' }, '✓ Signed') : h(Tag, null, 'Unsigned'); } },
    ];
    return h('div', { className: 'panel' },
      h('div', { className: 'panel-header' },
        h('div', null,
          h('div', { className: 'panel-title' }, 'Snapshots library'),
          h('div', { className: 'panel-sub' }, snaps.length + ' archived snapshots · stored at /domino/datasets/local/permissions_app/snapshots/')
        ),
        h(Button, { type: 'primary', onClick: props.onTakeSnapshot, loading: props.takingSnapshot },
          'Take snapshot now')
      ),
      snaps.length === 0
        ? h('div', { className: 'empty-state' },
            h('div', { className: 'empty-state-title' }, 'No snapshots yet'),
            h('div', { className: 'empty-state-body' }, 'Take your first snapshot to begin building an audit trail.'))
        : h(Table, { dataSource: snaps, columns: columns, rowKey: 'id', size: 'small',
            pagination: { pageSize: 25 } })
    );
  }

  // ---- Ask (locked-down compliance chat) ----------------------------------
  // Sends questions to /api/ask. The backend pattern-matches to one of ten
  // intents and returns structured rows from the snapshot — no LLM, no
  // generated prose. If the intent is unknown, the panel shows the canonical
  // supported questions instead of a free-form "answer".
  function AskPage(props) {
    var _q = useState(''); var q = _q[0]; var setQ = _q[1];
    var _busy = useState(false); var busy = _busy[0]; var setBusy = _busy[1];
    var _ex = useState([]); var examples = _ex[0]; var setExamples = _ex[1];
    var _hist = useState([]); var history = _hist[0]; var setHistory = _hist[1];

    useEffect(function () {
      apiGet('/api/ask/examples').then(function (r) { setExamples(r.questions || []); })
        .catch(function () {});
    }, []);

    function ask(question) {
      var qq = (question == null ? q : question).trim();
      if (!qq) return;
      setBusy(true);
      apiPostJson('/api/ask', { question: qq }).then(function (resp) {
        setHistory(function (prev) { return prev.concat([{ question: qq, response: resp }]); });
        setQ('');
      }).catch(function (e) {
        message.error('Ask failed: ' + e.message);
      }).finally(function () { setBusy(false); });
    }

    function renderSection(resp) {
      if (resp.intent === 'unknown') {
        return h('div', { className: 'ask-unknown' },
          h('div', { style: { marginBottom: 8 } }, resp.text),
          h('div', { style: { fontWeight: 600, marginTop: 8 } }, 'Supported questions:'),
          h('ul', { style: { margin: '6px 0 0 18px' } },
            (resp.examples || []).map(function (ex, i) {
              return h('li', { key: i, style: { fontSize: 13, marginBottom: 2 } },
                h('a', { onClick: function () { setQ(ex); }, style: { cursor: 'pointer' } }, ex));
            })));
      }
      var sections = resp.sections && resp.sections.length ? resp.sections : [resp];
      return h('div', null,
        sections.map(function (s, i) {
          var cols = (s.columns || []).map(function (c) {
            return { title: c.label, dataIndex: c.key, key: c.key, ellipsis: true,
              render: function (v) {
                if (v == null || v === '') return h('span', { className: 'text-muted' }, '—');
                if (Array.isArray(v)) return v.join(', ');
                return v;
              } };
          });
          return h('div', { key: i, style: { marginBottom: 12 } },
            sections.length > 1 ? h('div', { style: { fontWeight: 600, marginBottom: 6 } },
              s.text) : null,
            cols.length ? h(Table, {
              dataSource: s.rows || [], columns: cols, size: 'small',
              rowKey: function (r, idx) { return idx; },
              pagination: (s.rows || []).length > 25 ? { pageSize: 25 } : false,
              locale: { emptyText: 'No matching rows' },
            }) : null);
        }));
    }

    return h('div', null,
      h('div', { className: 'panel' },
        h('div', { className: 'panel-header' },
          h('div', null,
            h('div', { className: 'panel-title' }, 'Ask'),
            h('div', { className: 'panel-sub' },
              'Locked-down compliance Q&A. No external LLM. No model. Every answer is a deterministic query against the current snapshot — if the question isn\'t recognised, you get the list of supported forms, not a guess.')
          )
        ),
        h(Space.Compact, { style: { width: '100%' } },
          h(Input, { placeholder: 'e.g. Who has access to projects supply_risk_radar, target_scout, msl_field_insights and datasets sales_q1, sales_q2?',
            value: q, onChange: function (e) { setQ(e.target.value); },
            onPressEnter: function () { ask(); }, disabled: busy }),
          h(Button, { type: 'primary', onClick: function () { ask(); },
            loading: busy, disabled: !q.trim() }, 'Ask')
        ),
        examples.length ? h('div', { style: { marginTop: 10 } },
          h('div', { style: { fontSize: 12, color: '#65657B', marginBottom: 6 } },
            'Try one of:'),
          h('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 6 } },
            examples.map(function (ex, i) {
              return h(Tag, { key: i, style: { cursor: 'pointer' },
                onClick: function () { setQ(ex); ask(ex); } }, ex);
            }))
        ) : null
      ),
      history.slice().reverse().map(function (turn, i) {
        var resp = turn.response || {};
        return h('div', { key: i, className: 'panel', style: { marginBottom: 12 } },
          h('div', { style: { fontSize: 12, color: '#65657B', marginBottom: 4 } }, 'You asked'),
          h('div', { style: { fontWeight: 600, marginBottom: 8 } }, turn.question),
          h('div', { style: { fontSize: 12, color: '#65657B', marginBottom: 4 } },
            'Intent: ', h('code', null, resp.intent || '—'),
            resp.params ? ' · ' + JSON.stringify(resp.params) : ''),
          resp.text ? h('div', { style: { marginBottom: 10 } }, resp.text) : null,
          renderSection(resp),
          h('div', { style: { borderTop: '1px solid #E0E0E0', marginTop: 10, paddingTop: 8,
                              fontSize: 11, color: '#65657B' } },
            (resp.sources || []).map(function (s, j) {
              return h('div', { key: j }, '· ', s);
            }),
            resp.disclaimer ? h('div', { style: { marginTop: 4, fontStyle: 'italic' } },
              resp.disclaimer) : null
          ));
      })
    );
  }

  // ---- App shell -----------------------------------------------------------

  function App() {
    var _conn = useState(false); var connected = _conn[0]; var setConnected = _conn[1];
    var _hi = useState(null); var healthInfo = _hi[0]; var setHealthInfo = _hi[1];
    var _useDummy = useState(true); var useDummy = _useDummy[0]; var setUseDummy = _useDummy[1];
    var _page = useState('dashboard'); var page = _page[0]; var setPage = _page[1];
    var _loading = useState(false); var loading = _loading[0]; var setLoading = _loading[1];
    var _taking = useState(false); var taking = _taking[0]; var setTaking = _taking[1];

    var _snap = useState(null); var snap = _snap[0]; var setSnap = _snap[1];
    var _access = useState([]); var access = _access[0]; var setAccess = _access[1];
    var _priv = useState([]); var priv = _priv[0]; var setPriv = _priv[1];
    var _vols = useState([]); var vols = _vols[0]; var setVols = _vols[1];
    var _ds = useState([]); var datasets = _ds[0]; var setDatasets = _ds[1];
    var _dsrc = useState([]); var dataSources = _dsrc[0]; var setDataSources = _dsrc[1];
    var _snaps = useState([]); var snaps = _snaps[0]; var setSnaps = _snaps[1];

    function loadDummy() {
      setSnap(window.MOCK.snapshot);
      setAccess(window.MOCK.accessListing());
      setPriv(window.MOCK.privileged());
      setVols(window.MOCK.volumes());
      setDatasets(window.MOCK.datasets ? window.MOCK.datasets() : []);
      setDataSources(window.MOCK.dataSources ? window.MOCK.dataSources() : []);
      setSnaps([{ id: window.MOCK.snapshot.id, takenAt: window.MOCK.snapshot.takenAt, takenBy: 'demo',
        counts: window.MOCK.snapshot.counts, signed: false }]);
    }

    function loadLive() {
      setLoading(true);
      Promise.all([
        apiGet('/api/reports/access-listing'),
        apiGet('/api/reports/privileged'),
        apiGet('/api/reports/volumes'),
        apiGet('/api/reports/datasets'),
        apiGet('/api/reports/data-sources'),
        apiGet('/api/snapshots'),
      ]).then(function (results) {
        setSnap(results[0].snapshot);
        setAccess(results[0].rows || []);
        setPriv(results[1].rows || []);
        setVols(results[2].rows || []);
        setDatasets(results[3].rows || []);
        setDataSources(results[4].rows || []);
        setSnaps(results[5] || []);
      }).catch(function (e) {
        console.error('live load failed', e);
        message.error('Live data unavailable — switching to dummy data');
        setUseDummy(true);
        loadDummy();
      }).finally(function () { setLoading(false); });
    }

    // On mount: probe health, decide live vs dummy.
    useEffect(function () {
      apiGet('/api/health').then(function (hr) {
        setHealthInfo(hr || null);
        if (hr && hr.ok) {
          setConnected(true); setUseDummy(false); loadLive();
        } else {
          setConnected(false); setUseDummy(true); loadDummy();
        }
      }).catch(function () {
        setConnected(false); setUseDummy(true); loadDummy();
      });
    }, []);

    // Re-load when toggle flipped
    useEffect(function () {
      if (useDummy) loadDummy(); else if (connected) loadLive();
    }, [useDummy]);

    function takeSnapshot() {
      if (useDummy) { message.info('Dummy mode: snapshot not persisted'); return; }
      setTaking(true);
      apiPost('/api/snapshots').then(function () {
        message.success('Snapshot captured');
        loadLive();
      }).catch(function (e) {
        console.error(e); message.error('Snapshot failed: ' + e.message);
      }).finally(function () { setTaking(false); });
    }

    function exportReport(key, format) {
      if (useDummy) { message.info('Switch to live data to export'); return; }
      var url = apiUrl('/api/exports/' + key + '.' + format);
      window.open(url, '_blank');
    }

    var menuItems = [
      { key: 'dashboard', label: 'Dashboard' },
      { key: 'ask', label: 'Ask' },
      { key: 'users', label: 'User access listing' },
      { key: 'verify', label: 'Verify a user' },
      { key: 'privileged', label: 'Administrators' },
      { key: 'datasets', label: 'Datasets' },
      { key: 'data-sources', label: 'Data sources' },
      { key: 'volumes', label: 'External volumes' },
      { key: 'snapshots', label: 'Snapshots' },
      { key: 'debug', label: 'Debug' },
    ];

    var pageEl;
    if (page === 'dashboard') {
      pageEl = h(Dashboard, { snap: snap,
        onNav: setPage, onTakeSnapshot: takeSnapshot, takingSnapshot: taking });
    } else if (page === 'users') {
      pageEl = h(AccessListingPage, { rows: access, onExport: exportReport });
    } else if (page === 'privileged') {
      pageEl = h(PrivilegedPage, { rows: priv, onExport: exportReport });
    } else if (page === 'datasets') {
      pageEl = h(DatasetsPage, { rows: datasets, onExport: exportReport });
    } else if (page === 'data-sources') {
      pageEl = h(DataSourcesPage, { rows: dataSources, onExport: exportReport });
    } else if (page === 'volumes') {
      pageEl = h(VolumesPage, { rows: vols, onExport: exportReport });
    } else if (page === 'snapshots') {
      pageEl = h(SnapshotsPage, { snaps: snaps, onTakeSnapshot: takeSnapshot, takingSnapshot: taking });
    } else if (page === 'verify') {
      pageEl = h(VerifyUserPage, {});
    } else if (page === 'ask') {
      pageEl = h(AskPage, {});
    } else if (page === 'debug') {
      pageEl = h(DebugPage, {});
    }

    return h(ConfigProvider, { theme: dominoTheme },
      h('div', { className: 'app-layout-no-topnav' },
        h('div', { className: 'app-sider' },
          h('div', { className: 'brand' },
            h('div', { className: 'brand-title' }, 'Access Review'),
            h('div', { className: 'brand-sub' }, 'Domino · GxP-ready')
          ),
          h(Menu, { mode: 'inline', selectedKeys: [page],
            items: menuItems, onClick: function (e) { setPage(e.key); },
            style: { borderRight: 0 } })
        ),
        h('div', { className: 'main-content' },
          h('div', { className: 'search-card' },
            h('div', { className: 'search-card-identity' },
              h('span', { className: 'app-title' }, 'Domino Access Review'),
              h('span', { className: 'app-subtitle' }, 'Who has access to what — projects, datasets, and external volumes')
            ),
            h('div', { className: 'search-card-controls' },
              h(SnapshotBanner, { snapshot: snap, live: !useDummy && connected }),
              h('div', { className: 'dummy-data-toggle' },
                h(Tooltip, { title: connected ? 'Live data is available — toggle on to demo with mock data' : 'Live API unavailable — using dummy data' },
                  h('span', null, 'Dummy data')),
                h(Switch, { checked: useDummy, onChange: setUseDummy, size: 'small' })
              ),
              h(Button, { type: 'primary', onClick: takeSnapshot, loading: taking,
                disabled: useDummy }, 'Take snapshot')
            )
          ),
          (healthInfo && healthInfo.endpoints && !useDummy)
            ? (function () {
                var ep = healthInfo.endpoints;
                var gaps = [];
                if (!ep.datamount) gaps.push('External Data Volumes — /remotefs/v1/volumes returned empty (caller may lack cross-user volume visibility)');
                if (!ep.auditevents) gaps.push('Audit events — /api/audittrail/v1/search returned empty');
                if (!gaps.length) return null;
                return h(Alert, {
                  type: 'warning', showIcon: true, style: { marginBottom: 16 },
                  message: 'Known data gaps for this Domino instance',
                  description: h('ul', { style: { margin: '6px 0 0 16px', paddingLeft: 0 } },
                    gaps.map(function (g, i) { return h('li', { key: i, style: { fontSize: 12 } }, g); }))
                });
              })()
            : null,
          loading
            ? h('div', { style: { textAlign: 'center', padding: 60 } }, h(Spin, { size: 'large' }))
            : pageEl
        )
      )
    );
  }

  ReactDOM.createRoot(document.getElementById('root')).render(h(App));
})();
