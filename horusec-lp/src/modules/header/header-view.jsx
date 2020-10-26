import React from 'react';
import {Link} from 'gatsby';
import LogoHorussecSVG from '../../svgs/logo-horus.svg';
import IconGlobal from '../../svgs/icon-global-blue.svg';
import {Header} from './header-styled';
import NavigationComponent from '../../components/navigation';
import DropdownComponent from '../../components/dropdown';
import {LogoHorussec} from '../../components/image';

export default ({menuItems, languageItems, languageValue, isLanguageDropdownOpen, isMobileMenuOpen, toggleMobileMenu}) => {
  return (
    <Header className="row align-items-center justify-content-between">
      <div className="col-5 d-block d-md-none">
        <Link to="/">
          <LogoHorussec />
        </Link>
      </div>

      <div className="col-auto d-none d-md-flex">
        <Link to="/">
          <LogoHorussecSVG />
        </Link>
      </div>

      <div className="col-auto">
        <div className="row">
          <div className="col-auto order-2 order-md-1">
            <NavigationComponent items={menuItems} isMobileMenuOpen={isMobileMenuOpen} toggleMobileMenu={toggleMobileMenu} />
          </div>

          <div className="col-auto ml-2 order-1 order-md-2">
            <div className="row no-gutters align-items-center">
              <div className="col-auto d-flex">
                <IconGlobal />
              </div>

              <div className="col-auto ml-2">
                <DropdownComponent items={languageItems} value={languageValue} isItOpen={isLanguageDropdownOpen} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </Header>
  );
};
