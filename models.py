from flask_sqlalchemy import SQLAlchemy
import json
from encryption import CIPHER
from datetime import datetime
from sqlalchemy import and_, literal, ForeignKey
from sqlalchemy.sql import expression
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import foreign

db = SQLAlchemy()

class TargetConfig(db.Model):
    __tablename__ = 'target_config'
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)
    dc_ip = db.Column(db.String(45))
    target_subnets = db.Column(db.Text)
    username = db.Column(db.String(255))
    encrypted_password = db.Column(db.Text)

    assessment_runs = db.relationship('AssessmentRun', back_populates='target', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<TargetConfig {self.domain_name}>'

    @property
    def subnets(self):
        return json.loads(self.target_subnets) if self.target_subnets else []

    def set_target_subnets(self, subnets):
        self.target_subnets = json.dumps(subnets) if subnets else None

    def encrypt_password(self, password):
        if password:
            self.encrypted_password = CIPHER.encrypt(password.encode()).decode()
        else:
            self.encrypted_password = None

    def decrypt_password(self):
        if self.encrypted_password:
            return CIPHER.decrypt(self.encrypted_password.encode()).decode()
        return None

class AssessmentRun(db.Model):
    __tablename__ = 'assessment_run'
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('target_config.id'), nullable=False)
    status = db.Column(db.String(50), default='Not Started')
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    progress_task = db.Column(db.String(255))
    progress_percentage = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    selected_modules = db.Column(db.Text)
    users_count = db.Column(db.Integer, default=0)
    groups_count = db.Column(db.Integer, default=0)
    computers_count = db.Column(db.Integer, default=0)
    critical_findings = db.Column(db.Integer, default=0)
    high_findings = db.Column(db.Integer, default=0)
    medium_findings = db.Column(db.Integer, default=0)
    low_findings = db.Column(db.Integer, default=0)
    info_findings = db.Column(db.Integer, default=0)
    ntds_results = db.Column(db.JSON) # To store the list of extracted hashes [{'username': '...', 'ntlm_hash': '...'}]

    target = db.relationship('TargetConfig', back_populates='assessment_runs')
    findings = db.relationship('Finding', back_populates='assessment_run', cascade='all, delete-orphan')
    users = db.relationship('ADUser', back_populates='assessment_run', cascade='all, delete-orphan')
    groups = db.relationship('ADGroup', back_populates='assessment_run', cascade='all, delete-orphan')
    computers = db.relationship('ADComputer', back_populates='assessment_run', cascade='all, delete-orphan')
    password_policy = db.relationship('PasswordPolicy', back_populates='assessment_run', uselist=False, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<AssessmentRun {self.id} for {self.target_id}>'

    def set_selected_modules(self, modules):
        self.selected_modules = json.dumps(modules) if modules else None

    def get_selected_modules(self):
        return json.loads(self.selected_modules) if self.selected_modules else []

class Finding(db.Model):
    __tablename__ = 'finding'
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey('assessment_run.id'), nullable=False)
    type = db.Column(db.String(50), default='Vulnerability')
    severity = db.Column(db.String(50))
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    impact = db.Column(db.Text)
    remediation = db.Column(db.Text)
    affected_objects = db.Column(db.JSON)
    remediation_steps = db.Column(db.JSON) # To store a list of steps
    references = db.Column(db.JSON)       # To store a list of {'title': '...', 'url': '...'} dicts

    assessment_run = db.relationship('AssessmentRun', back_populates='findings')
    affected_users = db.relationship('ADUser', secondary='finding_user', back_populates='affected_findings')
    affected_groups = db.relationship('ADGroup', secondary='finding_group', back_populates='affected_findings')
    affected_computers = db.relationship('ADComputer', secondary='finding_computer', back_populates='affected_findings')

    def __repr__(self):
        return f'<Finding {self.title} ({self.severity})>'

class PasswordPolicy(db.Model):
    __tablename__ = 'password_policy'
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey('assessment_run.id'), nullable=False)
    min_length = db.Column(db.Integer)
    password_history = db.Column(db.Integer)
    max_age = db.Column(db.Integer)
    min_age = db.Column(db.Integer)
    lockout_threshold = db.Column(db.Integer)
    complexity = db.Column(db.Boolean)
    issues = db.Column(db.JSON)
    strength_counts = db.Column(db.JSON)

    assessment_run = db.relationship('AssessmentRun', back_populates='password_policy')
    user_password_stats = db.Column(db.JSON)

    def __repr__(self):
        return f'<PasswordPolicy for run {self.run_id}>'

# Define association tables first
finding_user = db.Table(
    'finding_user',
    db.Column('finding_id', db.Integer, db.ForeignKey('finding.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('ad_user.id'), primary_key=True)
)

finding_group = db.Table(
    'finding_group',
    db.Column('finding_id', db.Integer, db.ForeignKey('finding.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('ad_group.id'), primary_key=True)
)

finding_computer = db.Table(
    'finding_computer',
    db.Column('finding_id', db.Integer, db.ForeignKey('finding.id'), primary_key=True),
    db.Column('computer_id', db.Integer, db.ForeignKey('ad_computer.id'), primary_key=True)
)

class ADUser(db.Model):
    __tablename__ = 'ad_user'
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey('assessment_run.id'), nullable=False)
    username = db.Column(db.String(255))
    display_name = db.Column(db.String(255))
    sam_account_name = db.Column(db.String(255))
    user_principal_name = db.Column(db.String(255))
    distinguished_name = db.Column(db.Text)
    object_sid = db.Column(db.String(255))

    assessment_run = db.relationship('AssessmentRun', back_populates='users')
    affected_findings = db.relationship('Finding', secondary='finding_user', back_populates='affected_users')
    pwd_last_set = db.Column(db.DateTime)
    password_age_days = db.Column(db.Integer)
    password_expired = db.Column(db.Boolean)
    last_logon_timestamp = db.Column(db.DateTime)
    account_status = db.Column(db.String(50))
    # We'll define group_memberships after ADGroupMembership is defined

    def __repr__(self):
        return f'<ADUser {self.username}>'

class ADGroup(db.Model):
    __tablename__ = 'ad_group'
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey('assessment_run.id'), nullable=False)
    name = db.Column(db.String(255))
    distinguished_name = db.Column(db.Text)
    object_sid = db.Column(db.String(255))
    sam_account_name = db.Column(db.String(255))
    is_privileged = db.Column(db.Boolean, default=False)
    risk_level = db.Column(db.String(50))

    assessment_run = db.relationship('AssessmentRun', back_populates='groups')
    affected_findings = db.relationship('Finding', secondary='finding_group', back_populates='affected_groups')
    # We'll define memberships and member_of after ADGroupMembership is defined

    def __repr__(self):
        return f'<ADGroup {self.name}>'

class ADComputer(db.Model):
    __tablename__ = 'ad_computer'
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey('assessment_run.id'), nullable=False)
    name = db.Column(db.String(255))
    dns_hostname = db.Column(db.String(255))
    distinguished_name = db.Column(db.Text)
    object_sid = db.Column(db.String(255))
    sam_account_name = db.Column(db.String(255))
    operating_system = db.Column(db.String(255))

    assessment_run = db.relationship('AssessmentRun', back_populates='computers')
    affected_findings = db.relationship('Finding', secondary='finding_computer', back_populates='affected_computers')
    # We'll define group_memberships after ADGroupMembership is defined

    def __repr__(self):
        return f'<ADComputer {self.name}>'

class ADGroupMembership(db.Model):
    __tablename__ = 'ad_group_membership'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('ad_group.id'), nullable=False)
    member_type = db.Column(db.String(50))
    member_id = db.Column(db.Integer)
    depth = db.Column(db.Integer, default=1)

    group = db.relationship('ADGroup', foreign_keys=[group_id], backref='memberships')

    def __repr__(self):
        return f'<ADGroupMembership Group {self.group_id} Member {self.member_type} {self.member_id}>'

# Now add the relationships that depend on ADGroupMembership using foreign() to mark the columns
ADUser.group_memberships = db.relationship(
    'ADGroupMembership',
    primaryjoin=and_(
        ADGroupMembership.member_type == 'user',
        foreign(ADGroupMembership.member_id) == ADUser.id
    ),
    viewonly=True
)

ADGroup.member_of = db.relationship(
    'ADGroupMembership',
    primaryjoin=and_(
        ADGroupMembership.member_type == 'group',
        foreign(ADGroupMembership.member_id) == ADGroup.id
    ),
    viewonly=True
)

ADComputer.group_memberships = db.relationship(
    'ADGroupMembership',
    primaryjoin=and_(
        ADGroupMembership.member_type == 'computer',
        foreign(ADGroupMembership.member_id) == ADComputer.id
    ),
    viewonly=True
)

# Add the ApplicationUser class that was referenced in the error but not defined in the original code
class ApplicationUser(db.Model):
    __tablename__ = 'application_user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<ApplicationUser {self.username}>'