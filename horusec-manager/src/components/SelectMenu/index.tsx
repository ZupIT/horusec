import React, { CSSProperties } from 'react';
import MenuItem from '@material-ui/core/MenuItem';
import {
  ClickAwayListener,
  Grow,
  List,
  ListItem,
  ListItemText,
  MenuList,
  Paper,
  Popper,
} from '@material-ui/core';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';
import { kebabCase } from 'lodash';

interface Options {
  title: string;
  action: (params?: any) => void;
  style?: CSSProperties;
}

interface Props {
  options: Options[];
  title: string;
  value: string;
  fixItem?: Options;
}

export default function SelectMenu({ title, options, value, fixItem }: Props) {
  const [open, setOpen] = React.useState(false);
  const anchorRef = React.useRef<HTMLButtonElement>(null);
  const theme = getCurrentTheme();
  const handleToggle = () => {
    setOpen((prevOpen) => !prevOpen);
  };

  const handleClose = (event: React.MouseEvent<EventTarget>) => {
    if (
      anchorRef.current &&
      anchorRef.current.contains(event.target as HTMLElement)
    ) {
      return;
    }

    setOpen(false);
  };

  function handleListKeyDown() {
    // event: React.KeyboardEvent
    // if (event.key === "Tab") {
    //   event.preventDefault();
    //   setOpen(false);
    // }
  }

  // return focus to the button when we transitioned from !open -> open
  const prevOpen = React.useRef(open);
  React.useEffect(() => {
    if (prevOpen.current === true && open === false) {
      anchorRef.current.focus();
    }
    prevOpen.current = open;
  }, [open]);

  return (
    <div>
      <List component="nav" aria-label={title}>
        <ListItem
          button
          aria-haspopup="true"
          aria-controls={open ? 'menu-list-grow' : undefined}
          onClick={handleToggle}
          disableRipple
          style={{ padding: 0 }}
        >
          <ListItemText
            ref={anchorRef}
            primary={title}
            secondary={value}
            id={kebabCase(title)}
            color="secondary"
            primaryTypographyProps={{ color: 'secondary' }}
            secondaryTypographyProps={{ color: 'secondary' }}
          />
        </ListItem>
      </List>
      <Popper
        open={open}
        anchorEl={anchorRef.current}
        role={undefined}
        transition
        disablePortal
        style={{ zIndex: 999 }}
        tabIndex={0}
      >
        {({ TransitionProps, placement }) => (
          <Grow
            {...TransitionProps}
            style={{
              transformOrigin:
                placement === 'bottom' ? 'center top' : 'center bottom',
            }}
          >
            <Paper>
              <ClickAwayListener onClickAway={handleClose}>
                <MenuList
                  autoFocusItem={open}
                  id="menu-list-grow"
                  onKeyDown={handleListKeyDown}
                >
                  {options.map((item, index) => (
                    <MenuItem
                      key={index}
                      onClick={() => {
                        item.action();
                        handleToggle();
                      }}
                      style={item?.style}
                      id={kebabCase(item.title)}
                    >
                      {item.title}
                    </MenuItem>
                  ))}

                  {fixItem && (
                    <MenuItem
                      onClick={() => {
                        fixItem.action();
                        handleToggle();
                      }}
                      id={kebabCase(fixItem.title)}
                      style={{
                        ...fixItem?.style,
                        color: theme.colors.select.highlight,
                        textDecoration: 'underline',
                      }}
                    >
                      {fixItem.title}
                    </MenuItem>
                  )}
                </MenuList>
              </ClickAwayListener>
            </Paper>
          </Grow>
        )}
      </Popper>
    </div>
  );
}
