import React from 'react';
import {Menu, MenuItem, Sidebar, MobileMenu, MobileItem} from './navigation-styled';
import NavIconSVG from '../../svgs/navbar-icon.svg';
import IconClose from '../../svgs/icon-close.svg';

export default ({items, isMobileMenuOpen, toggleMobileMenu}) => {
  return (
    <nav>
      <Menu className="d-none d-md-flex">
        {items && items.length ? items.map((item) => (
            <MenuItem className="col-auto d-flex" key={item.id}>
              {item.content}
            </MenuItem>
          ))
        : null}
      </Menu>

      <div className="d-flex d-md-none">
        <NavIconSVG onClick={toggleMobileMenu} />
      </div>

      {isMobileMenuOpen ? (
        <Sidebar>
          <div className="row align-Items-end mb-3">
            <div className="col"></div>

            <div className="col-auto">
              <a href="/" onClick={toggleMobileMenu}>
                <IconClose />
              </a>
            </div>
          </div>

          <div className="row">
            <div className="col-12">
              <MobileMenu>{items && items.length ? items.map((item) => <MobileItem key={item.id}>{item.content}</MobileItem>) : null}</MobileMenu>
            </div>
          </div>
        </Sidebar>
      ) : null}
    </nav>
  );
};
