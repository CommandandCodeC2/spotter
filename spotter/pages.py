"""HTML pages."""
from flask import Blueprint, render_template, request

from . import storage
from .netmap import parse_network_map

bp = Blueprint('pages', __name__)


@bp.route('/')
def dashboard():
    return render_template('dashboard.html')


@bp.route('/network-map')
def network_map():
    return render_template(
        'network_map.html',
        nodes=parse_network_map(storage.network_map_path()),
        storyboard=storage.load_data()['storyboard'],
        success=request.args.get('success'),
        error=request.args.get('error'),
    )


@bp.route('/reports')
def reports():
    return render_template('reports.html')


@bp.route('/admin')
def admin():
    return render_template('admin.html')
