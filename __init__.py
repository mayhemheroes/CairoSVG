# -*- coding: utf-8 -*-
# This file is part of CairoSVG
# Copyright © 2010 Kozea
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with CairoSVG.  If not, see <http://www.gnu.org/licenses/>.

"""
CairoSVG: A simple SVG reader for Cairo

"""

from . import parser, surface


def svg2pdf(svg):
    """Return a PDF string corresponding to the ``svg`` string."""
    return surface.Surface(parser.Tree(svg)).read()